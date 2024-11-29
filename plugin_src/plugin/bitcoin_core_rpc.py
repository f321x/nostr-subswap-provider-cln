import traceback

import attr
from bitcoinrpc import BitcoinRPC, RPCError as BitcoinRPCError
from typing import Optional, Tuple, List
from httpx import Timeout as HttpxTimeout
import json
import asyncio
import time

from .cln_logger import PluginLogger
from .transaction import Transaction, PartialTxInput, TxOutpoint
from .utils import TxMinedInfo, descsum_create

class BitcoinCoreRPC:
    def __init__(self, logger: PluginLogger,
                        bcore_rpc_credentials: 'BitcoinRPCCredentials' = None):
        self._wallet_name = "cln-subswapplugin"
        self.iface = BitcoinRPC.from_config(url=bcore_rpc_credentials.url,
                                            auth=bcore_rpc_credentials.auth,
                                            wallet_name=self._wallet_name,)
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
                                       params=[wallet_name, True, True, "", False, True, True, False],
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
        await self._create_or_load_wallet(self._wallet_name)
        await self._validate_wallet_name(self._wallet_name)
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

        # Create a descriptor for the address
        descriptor = descsum_create(f"addr({address})")

        # Create the import request
        import_request = [{
            "desc": descriptor,
            "timestamp": "now",  # Use "now" to avoid rescanning
            "label": "swapplugin",
            "internal": False,
            "active": False  # We only want to watch the address, not make it active
        }]

        try:
            result = await self.iface.acall(
                method="importdescriptors",
                params=[import_request],
                timeout=HttpxTimeout(5)
            )

            # Check the result array
            if not result or len(result) == 0:
                raise BitcoinCoreRPCError("ChainMonitor register_address: Empty response from importdescriptors")

            import_result = result[0]  # Get first (and only) result, because we only imported one descriptor

            # Check for success
            if not import_result['success']:
                # If there's an error object, use it
                if 'error' in import_result:
                    error_msg = import_result['error']
                    raise BitcoinCoreRPCError(f"ChainMonitor register_address: Import failed: {error_msg}")
                # If there are warnings, include them
                elif 'warnings' in import_result:
                    warnings = ', '.join(import_result['warnings'])
                    raise BitcoinCoreRPCError(f"ChainMonitor register_address: Import failed with warnings: {warnings}")
                else:
                    raise BitcoinCoreRPCError("ChainMonitor register_address: Import failed without specific error")

        except BitcoinRPCError as e:
            if e.error["code"] == -4:
                raise WrongWalletLoadedError(
                    f"ChainMonitor: Legacy wallet loaded in bitcoin core, we need a descriptor wallet {e}"
                )
            raise BitcoinCoreRPCError(f"ChainMonitor register_address: Could not import address: {e}")

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
            utxos = await self.iface.acall(method="listunspent",
                                           params=[1, 9999999, [address]])
        except Exception:
            raise BitcoinCoreRPCError(f"ChainMonitor: get_addr_outputs call for {address} failed: {traceback.format_exc()}")
        if len(received) == 0:
            raise UnknownAddressError(f"ChainMonitor: get_addr_outputs: Address {address} hasn't been imported before")

        received_txids = received[0]['txids']  # all txids of transactions that spent to 'address'
        if len(received_txids) == 0:  # no txids, no utxos
            self._logger.debug(f"ChainMonitor: get_addr_outputs: Address {address} has no received txids")
            return funding_inputs

        for utxo in utxos:
            funding_inputs.append(await self._utxo_to_partial_txin(utxo))
        unspent_amount_sat = sum([utxo.value_sats() for utxo in funding_inputs])
        spent_amount = int(float(received[0]['amount']) * 10**8) - unspent_amount_sat
        if spent_amount > 0:  # nothing received to the address has been spent yet
            # at least some utxos have been spent again already, so we have to fetch the spending txs
            spent_utxos = await self._fetch_spent_utxos(received_txids, spent_amount, address)
            if spent_amount - sum([utxo.value_sats() for utxo in spent_utxos]) > 0:
                raise UtxosNotFoundError(f"ChainMonitor: get_addr_outputs: "
                                           f"Could not find all spent utxos for {address}")
        return funding_inputs

    async def _utxo_to_partial_txin(self, utxo: dict) -> PartialTxInput:
        """Convert a utxo dict to a PartialTxInput object"""
        future_prevout = TxOutpoint(txid=bytes.fromhex(utxo['txid']), out_idx=utxo['vout'])
        part_txin = PartialTxInput(prevout=future_prevout, is_coinbase_output=False)  # rpc call doesn't return coinbase outputs
        part_txin._trusted_address = utxo['address']
        part_txin._trusted_value_sats = int(utxo['amount'] * 10**8)
        part_txin.block_height = await self.get_tx_height(utxo['txid'])
        part_txin.block_txpos = utxo.get('blockindex', None)
        part_txin.spent_height = utxo.get('spent_height', None)
        part_txin.spent_txid = utxo.get('spent_txid', None)
        return part_txin

    async def _fetch_spent_utxos(self, received_txids: List[str], spent_amount_sat: int,
                                 locking_addr: str) -> List[PartialTxInput]:
        fetch_txs = 1  # amount of transactions to fetch
        spent_utxos = []

        # we look for the spending transactions and deduct the amount once found
        while spent_amount_sat > 0:
            try:
                wallet_txs = json.loads(await self.iface.acall(method="listwallettransactions",
                                                    params=["*", fetch_txs, fetch_txs - 1, True],
                                                    timeout=HttpxTimeout(5)))
            except Exception as e:
                raise BitcoinCoreRPCError(f"ChainMonitor: _fetch_spent_utxos: Could not get wallet transactions: {e}")
            fetch_txs += 1
            if len(wallet_txs) == 0 or fetch_txs > 200:  # no more txs to fetch
                return spent_utxos
            wallet_send_tx = wallet_txs[0] if wallet_txs[0]["category"] == "send" else None
            if not wallet_send_tx:  # fetched tx was no outgoing tx, ignoring it
                continue
            full_spending_tx = await self.get_transaction(wallet_send_tx["txid"])
            for txin in full_spending_tx.inputs():
                if txin.prevout.txid.hex() in received_txids:
                    # the spending tx is spending an output of a transaction that also spent to our address
                    full_received_tx = await self.get_transaction(txin.prevout.txid.hex())  # tx we received to locking_addr
                    # now we have to find if the spent prevout was locked to our address
                    spent_output = full_received_tx.outputs()[txin.prevout.out_idx]
                    if spent_output.address == locking_addr:
                        # this is the utxo that has been spent again
                        utxo = {
                            "txid": txin.prevout.txid.hex(),
                            "vout": txin.prevout.out_idx,
                            "address": locking_addr,
                            "amount": spent_output.value,
                            "spent_height": wallet_send_tx.get("blockheight", None),
                            "spent_txid": wallet_send_tx["txid"]
                        }
                        spent_utxos.append(await self._utxo_to_partial_txin(utxo))
                        spent_amount_sat -= spent_output.value
        return spent_utxos


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

class UtxosNotFoundError(Exception):
    pass
