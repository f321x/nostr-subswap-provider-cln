from typing import Callable, Optional, List

from httpx import Timeout as HttpxTimeout
from bitcoinrpc import BitcoinRPC, RPCError as BitcoinRPCError
import time
import asyncio

from .cln_logger import PluginLogger
from .utils import TxMinedInfo, BitcoinRPCCredentials
from .transaction import Transaction, TxOutpoint, PartialTxInput

class ChainMonitor:
    def __init__(self, logger: PluginLogger, bcore_rpc_credentials: BitcoinRPCCredentials = None,
                 bcore_rpc: BitcoinRPC = None) -> None:
        """Takes the bitcoin core rpc config from cln and uses bcore as chain backend"""
        if bcore_rpc is not None:
            self.bcore = bcore_rpc
        elif bcore_rpc_credentials is not None:
            self.bcore = BitcoinRPC.from_config(url=bcore_rpc_credentials.url,
                                                auth=bcore_rpc_credentials.auth)
        else:
            raise Exception("ChainMonitor: No Bitcoin Core rpc config found")
        self._logger = logger
        self.callbacks = {}
        self.monitoring_task = None

    async def _test_connection(self) -> None:
        """Test the connection to the Bitcoin Core node"""
        try:
            result = await self.bcore.getblockchaininfo()
            self._logger.debug(f"ChainMonitor: Connected to Bitcoin Core: {result}")
            assert result["blocks"] > 10  # simple sanity check of result
        except Exception as e:
            raise ChainMonitorNotConnectedError(f"ChainMonitor: Could not connect to Bitcoin Core: {e}")

    async def _txindex_enabled(self) -> bool:
        """Check if txindex is enabled"""
        try:
            result = await self.bcore.acall(method="getindexinfo", params=[], timeout=HttpxTimeout(5))
            self._logger.debug(f"ChainMonitor: _txindex_enabled: {result}")
            if not result.get("txindex", False) or not result["txindex"].get("synced", False):
                return False
            return True
        except Exception as e:
            raise ChainMonitorRpcError(f"ChainMonitor _txindex_enabled: Could not get blockchain info: {e}")

    async def _create_or_load_wallet(self) -> None:
        """We create or load an existing wallet without private keys to look up addresses.
        This wallet won't be used for to control any funds, only to monitor addresses."""
        try:
            await self.bcore.acall(method="loadwallet", params=["cln-subswapplugin", True], timeout=HttpxTimeout(5))
        except BitcoinRPCError as e:
            if e.error["code"] == -35:
                self._logger.debug("ChainMonitor _create_or_load_wallet: Wallet already loaded")
                return
            elif e.error["code"] == -18:
                self._logger.debug("ChainMonitor _create_or_load_wallet: Wallet not found, creating...")
            else:
                raise ChainMonitorRpcError(f"ChainMonitor _create_or_load_wallet: Could not load wallet: {e}")

            # wallet is not loaded if we didn't return above
            try:
                await self.bcore.acall(method="createwallet",
                                       params=["cln-subswapplugin", True, True, "", False, False, True],
                                       timeout=HttpxTimeout(5))
            except BitcoinRPCError as e:
                raise ChainMonitorRpcError(f"ChainMonitor _create_or_load_wallet: Could not create wallet: {e}")

    async def _validate_wallet_name(self, wallet_name: str) -> None:
        """Check if the correct wallet is loaded (and not some other wallet)"""
        try:
            wallet_info = await self.bcore.acall(method="getwalletinfo", params=[], timeout=HttpxTimeout(5))
            if wallet_info["walletname"] != wallet_name:
                raise WrongWalletLoadedError(f"ChainMonitor: Wallet name mismatch: {wallet_info['walletname']}")
        except BitcoinRPCError as e:
            raise ChainMonitorRpcError(f"ChainMonitor: Could not get wallet info: {e}")

    async def run(self) -> None:
        """Run the chain monitor"""
        await self._test_connection()
        if not await self._txindex_enabled():
            raise ChainMonitorRpcError("ChainMonitor: txindex is not enabled")
        await self._create_or_load_wallet()
        await self._validate_wallet_name("cln-subswapplugin")
        while not await self.is_up_to_date():
            self._logger.info("ChainMonitor: Waiting for chain to sync")
            await asyncio.sleep(10)
        self.monitoring_task = asyncio.create_task(self.monitoring_loop())
        self._logger.debug("ChainMonitor: Running...")

    async def monitoring_loop(self) -> None:
        """Main monitoring loop, triggering callbacks on each new block"""
        last_height = await self.get_local_height()
        while True:
            await asyncio.sleep(10)
            try:
                blockheight = await self.get_local_height()
                if blockheight > last_height:
                    self._logger.debug(f"ChainMonitor: New blockheight: {blockheight}")
                    last_height = blockheight
                    await self.trigger_callbacks()
            except Exception as e:
                self._logger.error(f"ChainMonitor: Error in monitoring loop: {e}")

    async def trigger_callbacks(self) -> None:
        """Trigger all callbacks for monitored addresses"""
        for callback in self.callbacks.values():
            try:
                await callback()
            except Exception as e:
                self._logger.error(f"ChainMonitor: Error in chain callback: {e}")

    async def import_address_to_monitor(self, address: str) -> None:
        """Add an address to the wallet so bitcoin core begins monitoring it. This should happen right after creation
        so we don't have to rescan which would be very slow."""
        timestamp = int(time.time())
        try:
            await self.bcore.acall(method="importaddress",
                                   params=[address, f"swapplugin({timestamp})", False, False],
                                   timeout=HttpxTimeout(5))
        except BitcoinRPCError as e:
            raise ChainMonitorRpcError(f"ChainMonitor import_address_to_monitor: Could not import address: {e}")

    def add_callback(self, lookup_address, callback: Callable) -> None:
        self._logger.debug(f"ChainMonitor: Adding callback for address {lookup_address}")
        self.callbacks[lookup_address] = callback

    def remove_callback(self, lookup_address) -> None:
        self._logger.debug(f"ChainMonitor: Removing callback for address {lookup_address}")
        self.callbacks.pop(lookup_address)

    async def is_up_to_date(self) -> bool:
        """We check if bcore is fully synced as best as we can"""
        try:
            result = await self.bcore.getblockchaininfo()
            if result["blocks"] < 10:  # simple sanity check of result
                raise ChainMonitorRpcError("ChainMonitor is_up_to_date: Not enough blocks")
            if not result["blocks"] == result["headers"]:
                return False

            blockheader = await self.bcore.getblockheader(block_hash=result["bestblockhash"],
                                                   verbose=True)
            # if last block is older than 60 minutes something is probably wrong and we should wait
            if blockheader["time"] < time.time() - 60 * 60:
                return False
        except Exception as e:
            raise ChainMonitorRpcError(f"ChainMonitor is_up_to_date: Could not get blockchain info: {e}")
        return True

    async def get_tx_height(self, txid_hex: str) -> TxMinedInfo:
        try:
            raw_tx = await self.bcore.getrawtransaction(txid=txid_hex, verbose=True)

            height = None
            if raw_tx["confirmations"] > 0:
                blockheader = await self.bcore.getblockheader(block_hash=raw_tx["blockhash"], verbose=True)
                height = blockheader["height"]

            return TxMinedInfo(
                height=height,
                conf=raw_tx["confirmations"],
                timestamp=raw_tx["blocktime"],
                txpos=None,  # we don't have this info and don't need it
                header_hash=raw_tx["blockhash"],
                wanted_height=raw_tx["locktime"] if raw_tx["locktime"] > 0 else None,
            )
        except Exception as e:
            raise ChainMonitorRpcError(f"ChainMonitor get_tx_height: Could not get raw transaction: {e}")

    async def get_transaction(self, txid_hex: str) -> Optional[Transaction]:
        """getrawtransaction into Transaction object"""
        self._logger.debug(f"ChainMonitor: get_transaction: {txid_hex}")
        try:
            raw_tx = await self.bcore.getrawtransaction(txid=txid_hex, verbose=False)
            return Transaction(raw=raw_tx)
        except BitcoinRPCError as e:
            if e.error["code"] == -5:  # No such mempool or blockchain transaction.
                return None
            raise ChainMonitorRpcError(f"ChainMonitor get_transaction: Could not get raw transaction {txid_hex}: {e}")
        except Exception as e:
            raise ChainMonitorRpcError(f"ChainMonitor get_transaction: Could not get raw transaction {txid_hex}: {e}")

    async def get_local_height(self) -> int:
        try:
            height = await self.bcore.getblockcount()
            assert isinstance(height, int)
            assert height >= 10, f"ChainMonitor get_local_height: sanity check: Not enough blocks: {height}"
            return height
        except Exception as e:
            raise ChainMonitorRpcError(f"ChainMonitor get_local_height: Could not get blockcount: {e}")

    async def get_addr_outputs(self, address: str) -> List[PartialTxInput]:
        funding_inputs: List[PartialTxInput] = []


    def remove_tx(self, txid_hex: str) -> None:
        """Removes a transaction AND all its dependents/children
            from the wallet history."""
        pass


class ChainMonitorRpcError(Exception):
    pass

class ChainMonitorNotConnectedError(Exception):
    pass

class WrongWalletLoadedError(Exception):
    pass
