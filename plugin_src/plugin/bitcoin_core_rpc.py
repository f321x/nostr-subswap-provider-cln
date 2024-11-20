import attr
from bitcoinrpc import BitcoinRPC, RPCError as BitcoinRPCError
from typing import Optional, Tuple, List
from httpx import Timeout as HttpxTimeout
import json
import asyncio
import time

from .cln_logger import PluginLogger
from .transaction import Transaction, PartialTxInput, TxOutpoint
from .utils import TxMinedInfo

class BitcoinCoreRPC:
    def __init__(self, logger: PluginLogger,
                        bcore_rpc_credentials: 'BitcoinRPCCredentials' = None):
        self.iface = BitcoinRPC.from_config(url=bcore_rpc_credentials.url,
                                            auth=bcore_rpc_credentials.auth)
        self._logger = logger

    async def _test_connection(self) -> None:
        """Test the connection to the Bitcoin Core node"""
        try:
            result = await self.iface.getblockchaininfo()
            self._logger.debug(f"ChainMonitor: Connected to Bitcoin Core: {result}")
            assert result["blocks"] > 10  # simple sanity check of result
        except Exception as e:
            raise BitcoinCoreRPCError(f"ChainMonitor: Could not connect to Bitcoin Core: {e}")

    async def _txindex_enabled(self) -> bool:
        """Check if txindex is enabled"""
        try:
            result = await self.iface.acall(method="getindexinfo", params=[], timeout=HttpxTimeout(5))
            self._logger.debug(f"ChainMonitor: _txindex_enabled: {result}")
            if not result.get("txindex", False) or not result["txindex"].get("synced", False):
                return False
            return True
        except Exception as e:
            raise BitcoinCoreRPCError(f"ChainMonitor _txindex_enabled: Could not get blockchain info: {e}")

    async def _create_or_load_wallet(self, wallet_name: str) -> None:
        """We create or load an existing wallet without private keys to look up addresses.
        This wallet won't be used for to control any funds, only to monitor addresses."""
        try:
            await self.iface.acall(method="loadwallet", params=[wallet_name, True], timeout=HttpxTimeout(5))
        except BitcoinRPCError as e:
            if e.error["code"] == -35:
                self._logger.debug("ChainMonitor _create_or_load_wallet: Wallet already loaded")
                return
            elif e.error["code"] == -18:
                self._logger.debug("ChainMonitor _create_or_load_wallet: Wallet not found, creating...")
            else:
                raise BitcoinCoreRPCError(f"ChainMonitor _create_or_load_wallet: Could not load wallet: {e}")

            # wallet is not loaded if we didn't return above
            try:
                await self.iface.acall(method="createwallet",
                                       params=[wallet_name, True, True, "", False, False, True],
                                       timeout=HttpxTimeout(5))
            except BitcoinRPCError as e:
                raise BitcoinCoreRPCError(f"ChainMonitor _create_or_load_wallet: Could not create wallet: {e}")

    async def _validate_wallet_name(self, wallet_name: str) -> None:
        """Check if the correct wallet is loaded (and not some other wallet, e.g. through other application)"""
        try:
            wallet_info = await self.iface.acall(method="getwalletinfo", params=[], timeout=HttpxTimeout(5))
            if wallet_info["walletname"] != wallet_name:
                raise WrongWalletLoadedError(f"ChainMonitor: Wallet name mismatch: {wallet_info['walletname']}")
        except BitcoinRPCError as e:
            raise BitcoinCoreRPCError(f"ChainMonitor: Could not get wallet info: {e}")

    async def _init(self):
        """Initialize the Bitcoin Core RPC connection"""
        assert self.iface is not None, "ChainMonitor: Bitcoin Core RPC interface not set"
        assert self._logger is not None, "ChainMonitor: Logger not set"
        await self._test_connection()
        if not await self._txindex_enabled():
            raise BitcoinCoreRPCError("ChainMonitor: txindex is not enabled")
        await self._create_or_load_wallet("cln-subswapplugin")
        await self._validate_wallet_name("cln-subswapplugin")
        while not await self.is_up_to_date():
            self._logger.info("ChainMonitor: Waiting for chain to sync")
            await asyncio.sleep(10)
        self._logger.debug("Bitcoin Core RPC connection: Initialized")

    async def is_up_to_date(self) -> bool:
        """We check if bcore is fully synced as best as we can"""
        try:
            result = await self.iface.getblockchaininfo()
            if result["blocks"] < 10:  # simple sanity check of result
                raise BitcoinCoreRPCError("ChainMonitor is_up_to_date: Not enough blocks")
            if not result["blocks"] == result["headers"]:
                return False

            blockheader = await self.iface.getblockheader(block_hash=result["bestblockhash"],
                                                          verbose=True)
            # if last block is older than 60 minutes something is probably wrong and we should wait
            if blockheader["time"] < time.time() - 60 * 60:
                return False
        except Exception as e:
            raise BitcoinCoreRPCError(f"ChainMonitor is_up_to_date: Could not get blockchain info: {e}")
        return True

    async def register_address(self, address: str) -> None:
        """Add an address to the wallet so bitcoin core begins monitoring it. This should happen right after creation
        so we don't have to rescan which would be very slow."""
        timestamp = int(time.time())
        try:
            await self.iface.acall(method="importaddress",
                                   params=[address, f"swapplugin", False, False],
                                   timeout=HttpxTimeout(5))
        except BitcoinRPCError as e:
            if e.error["code"] == -4:
                raise WrongWalletLoadedError(f"ChainMonitor: "
                                             f"Descriptor wallet loaded in bitcoin core, we need a legacy wallet {e}")
            raise BitcoinCoreRPCError(f"ChainMonitor import_address_to_monitor: Could not import address: {e}")

    async def get_tx_height(self, txid_hex: str) -> TxMinedInfo:
        try:
            raw_tx = await self.iface.getrawtransaction(txid=txid_hex, verbose=True)

            height = None
            if raw_tx["confirmations"] > 0:
                blockheader = await self.iface.getblockheader(block_hash=raw_tx["blockhash"], verbose=True)
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
            raise BitcoinCoreRPCError(f"ChainMonitor get_tx_height: Could not get raw transaction: {e}")

    async def get_transaction(self, txid_hex: str) -> Optional[Transaction]:
        """getrawtransaction into Transaction object"""
        self._logger.debug(f"ChainMonitor: get_transaction: {txid_hex}")
        try:
            raw_tx = await self.iface.getrawtransaction(txid=txid_hex, verbose=False)
            return Transaction(raw=raw_tx)
        except BitcoinRPCError as e:
            if e.error["code"] == -5:  # No such mempool or blockchain transaction.
                return None
            raise BitcoinCoreRPCError(f"ChainMonitor get_transaction: Could not get raw transaction {txid_hex}: {e}")
        except Exception as e:
            raise BitcoinCoreRPCError(f"ChainMonitor get_transaction: Could not get raw transaction {txid_hex}: {e}")

    async def get_local_height(self) -> int:
        try:
            height = await self.iface.getblockcount()
            assert isinstance(height, int)
            assert height >= 10, f"ChainMonitor get_local_height: sanity check: Not enough blocks: {height}"
            return height
        except Exception as e:
            raise BitcoinCoreRPCError(f"ChainMonitor get_local_height: Could not get blockcount: {e}")

    async def get_addr_outputs(self, address: str) -> List[PartialTxInput]:
        """Getting utxos for the address in form of a PartialTxInput. The utxo will be marked spent
        if it has already been spent again"""
        funding_inputs: List[PartialTxInput] = []

        # get all transactions that spent to the address
        try:  # minconf, include_empty, include_watchonly, address_filter, include_immature_cb
            received = json.loads(await self.iface.acall(method="listreceivedbyaddress",
                                              params=[1, True, True, address, False]))
            utxos = json.loads(await self.iface.acall(method="listunspent",
                                           params=[1, 9999999, [address]]))
        except Exception as e:
            raise BitcoinCoreRPCError(f"ChainMonitor: get_addr_outputs call for {address} failed: {e}")
        if len(received) == 0:
            raise UnknownAddressError(f"ChainMonitor: get_addr_outputs: Address {address} hasn't been imported before")

        received_txids = received[0]['txids']  # all txids of transactions that spent to 'address'
        if len(received_txids) == 0:  # no txids, no utxos
            self._logger.debug(f"ChainMonitor: get_addr_outputs: Address {address} has no received txids")
            return funding_inputs

        for utxo in utxos:
            funding_inputs.append(await self._utxo_to_partial_txin(utxo))
        unspent_amount_sat = sum([utxo._trusted_value_sats for utxo in funding_inputs])
        spent_amount = int(float(received[0]['amount']) * 10**8) - unspent_amount_sat
        if spent_amount > 0:  # nothing received to the address has been spent yet
            # at least some utxos have been spent again already, so we have to fetch the spending txs
            spent_utxos = await self._fetch_spent_utxos(received_txids, spent_amount)

        return funding_inputs

    async def _utxo_to_partial_txin(self, rpc_utxo: dict) -> PartialTxInput:
        """Convert a utxo dict to a PartialTxInput object"""
        future_prevout = TxOutpoint(txid=bytes.fromhex(rpc_utxo['txid']), out_idx=rpc_utxo['vout'])
        utxo = PartialTxInput(prevout=future_prevout, is_coinbase_output=False)  # rpc call doesn't return coinbase outputs
        utxo._trusted_address = rpc_utxo['address']
        utxo._trusted_value_sats = int(rpc_utxo['amount'] * 10**8)
        utxo.block_height = await self.get_tx_height(rpc_utxo['txid'])
        utxo.block_txpos = None  # we don't need this for swaps
        utxo.spent_height = None # is not spent because it was returned by listunspent
        utxo.spent_txid = None
        return utxo

    async def _fetch_spent_utxos(self, received_txids: List[str], spent_amount_sat: int) -> None:
        fetch_txs = 1  # amount of transactions to fetch

        # we look for the spending transactions and deduct the amount once found
        while spent_amount_sat > 0:
            try:
                wallet_txs = json.loads(await self.iface.acall(method="listwallettransactions",
                                                    params=["*", fetch_txs, fetch_txs - 1, True],
                                                    timeout=HttpxTimeout(5)))
            except Exception as e:
                raise BitcoinCoreRPCError(f"ChainMonitor: _fetch_spent_utxos: Could not get wallet transactions: {e}")
            fetch_txs += 1
            if len(wallet_txs) == 0:  # no more txs to fetch
                return None
            wallet_send_tx = wallet_txs[0] if wallet_txs[0]["category"] == "send" else None
            if not wallet_send_tx:  # fetched tx was no outgoing tx, ignoring it
                continue
            full_tx = await self.get_transaction(wallet_send_tx["txid"])
            for input in full_tx.inputs():
                if input.prevout.txid.hex() in received_txids:
                #     spent_amount_sat -= input.prevout.value_sats
                #     if spent_amount_sat <= 0:
                #         return None
                # send_tx
                # {
                #     "involvesWatchonly": true,
                #     "address": "tb1qd28npep0s8frcm3y7dxqajkcy2m40eysplyr9v",
                #     "category": "send",
                #     "amount": -0.00009714,
                #     "vout": 0,
                #     "fee": -0.00000286,
                #     "confirmations": 626,
                #     "blockhash": "000002c469b8c5b18661b5bf8aacd5190370acde2ad0d91f654902effa5652bb",
                #     "blockheight": 1617298,
                #     "blockindex": 1,
                #     "blocktime": 1732094921,
                #     "txid": "20d8faa365e1a35a0a31f1887488c6409bd3d17c2c5a702b59e26d3dc44b7e8f",
                #     "wtxid": "4a6dc8ea4079e3012a3b7f98ea262739c8b074889c2faa631bffd125e01da0dc",
                #     "walletconflicts": [
                #     ],
                #     "time": 1732094921,
                #     "timereceived": 1732094921,
                #     "bip125-replaceable": "no",
                #     "abandoned": false
                # }


@attr.s(frozen=True, auto_attribs=True, kw_only=True)
class BitcoinRPCCredentials:
    """Credentials for Bitcoin Core RPC."""
    host: str
    port: int
    user: str
    password: str
    datadir: Optional[str] = None
    timeout: int = attr.ib(default=60, validator=attr.validators.instance_of(int))

    @classmethod
    def from_cln_config_dict(cls, cln_config: dict) -> "BitcoinRPCCredentials":
        """Load the credentials from the cln config dict fetched with lightning-listconfigs"""
        return cls(
            host=cln_config["bitcoin-rpcconnect"]["value_str"],
            port=cln_config["bitcoin-rpcport"]["value_int"],
            user=cln_config["bitcoin-rpcuser"]["value_str"],
            password=cln_config["bitcoin-rpcpassword"]["value_str"],
            datadir=cln_config.get("bitcoin-datadir", {}).get("value_str"),
            timeout=cln_config.get("bitcoin-rpcclienttimeout", {}).get("value_int", 60)
        )

    def __str__(self) -> str:
        """Return a string representation of the credentials for pretty debugging"""
        components = [
            f"Bitcoin RPC Credentials:",
            f"  URL: {self.url}",
            f"  User: {self.user}",
            f"  Password: {self.password}",
        ]
        if self.datadir:
            components.append(f"  Data Directory: {self.datadir}")
        components.append(f"  Timeout: {self.timeout}s")
        return '\n'.join(components)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def auth(self) -> Tuple[str, str]:
        """Auth format required for bitcoinrpc lib"""
        return self.user, self.password


class BitcoinCoreRPCError(Exception):
    pass

class WrongWalletLoadedError(Exception):
    pass

class BitcoinCoreNotConnectedError(Exception):
    pass

class UnknownAddressError(Exception):
    pass
