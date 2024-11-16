from typing import Callable, Optional, Dict

from httpx import Timeout as HttpxTimeout
from bitcoinrpc import BitcoinRPC, RPCError as BitcoinRPCError
import time

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
        self.monitored_addresses = set()
        self.callbacks = {}

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

    async def run(self) -> None:
        """Run the chain monitor"""
        await self._test_connection()
        if not await self._txindex_enabled():
            raise ChainMonitorRpcError("ChainMonitor: txindex is not enabled")
        pass  # TODO: Implement callback monitoring

    def add_callback(self, lookup_address, callback: Callable) -> None:
        self._logger.debug(f"ChainMonitor: Adding callback for address {lookup_address}")
        self.monitored_addresses.add(lookup_address)
        self.callbacks[lookup_address] = callback

    def remove_callback(self, lookup_address) -> None:
        self._logger.debug(f"ChainMonitor: Removing callback for address {lookup_address}")
        self.monitored_addresses.remove(lookup_address)
        self.callbacks.pop(lookup_address)

    async def is_up_to_date(self) -> bool:
        """We check if bcore is fully synced as best as we can"""
        try:
            result = await self.bcore.getblockchaininfo()
            if result["blocks"] < 10:  # simple sanity check of result
                raise ChainMonitorRpcError("ChainMonitor is_up_to_date: Not enough blocks")
            if not result["blocks"] == result["headers"]:
                return False

            best_block_time = await self.bcore.getblockheader(block_hash=result["bestblockhash"],
                                                   verbose=True)["time"]
            # if last block is older than 60 minutes something is probably wrong and we should wait
            if best_block_time < time.time() - 60 * 60:
                return False
        except Exception as e:
            raise ChainMonitorRpcError(f"ChainMonitor is_up_to_date: Could not get blockchain info: {e}")
        return True

    def get_tx_height(self, txid_hex: str) -> TxMinedInfo:
        try:
            height = self.bcore.getblockcount()
            raw_tx = self.bcore.getrawtransaction(txid=txid_hex, verbose=True)
            return TxMinedInfo(
                height=raw_tx["confirmations"] - height if raw_tx["confirmations"] > 0 else None,
                conf=raw_tx["confirmations"],
                timestamp=raw_tx["blocktime"],
                txpos=None,  # we don't have this info and don't need it
                header_hash=raw_tx["blockhash"],
                wanted_height=raw_tx["locktime"] if raw_tx["locktime"] > 0 else None,
            )
        except Exception as e:
            raise ChainMonitorRpcError(f"ChainMonitor get_tx_height: Could not get raw transaction: {e}")

    def get_transaction(self, txid_hex: str) -> Optional[Transaction]:
        """getrawtransaction into Transaction object"""
        self._logger.debug(f"ChainMonitor: get_transaction: {txid_hex}")
        try:
            raw_tx = self.bcore.getrawtransaction(txid=txid_hex, verbose=False)
            return Transaction(raw=raw_tx)
        except BitcoinRPCError as e:
            if e.error["code"] == -5:  # No such mempool or blockchain transaction.
                return None
            raise ChainMonitorRpcError(f"ChainMonitor get_transaction: Could not get raw transaction {txid_hex}: {e}")
        except Exception as e:
            raise ChainMonitorRpcError(f"ChainMonitor get_transaction: Could not get raw transaction {txid_hex}: {e}")

    def get_addr_outputs(self, address: str) -> Dict[TxOutpoint, PartialTxInput]:
        pass

    def remove_tx(self, txid_hex: str) -> None:
        """Removes a transaction AND all its dependents/children
            from the wallet history."""
        pass


class ChainMonitorRpcError(Exception):
    pass

class ChainMonitorNotConnectedError(Exception):
    pass
