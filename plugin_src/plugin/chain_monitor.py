from typing import Callable, Optional, Dict
from bitcoinrpc import BitcoinRPC
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
        self.monitored_addresses = set()
        self.callbacks = {}

    async def _test_connection(self) -> None:
        """Test the connection to the Bitcoin Core node"""
        try:
            result = await self.bcore.getblockchaininfo()
            assert result["blocks"] > 10  # simple sanity check of result
        except Exception as e:
            raise ChainMonitorNotConnectedError(f"ChainMonitor: Could not connect to Bitcoin Core: {e}")

    async def run(self) -> None:
        """Run the chain monitor"""
        await self._test_connection()
        pass  # TODO: Implement

    def add_callback(self, lookup_address, callback: Callable) -> None:
        self.monitored_addresses.add(lookup_address)
        self.callbacks[lookup_address] = callback

    def remove_callback(self, lookup_address) -> None:
        self.monitored_addresses.remove(lookup_address)
        self.callbacks.pop(lookup_address)

    async def is_up_to_date(self) -> bool:
        """We check if bcore is fully synced"""
        try:
            result = await self.bcore.getblockchaininfo()
            if not result["blocks"] == result["headers"]:
                return False

            best_block_time = await self.bcore.getblock(block_hash=result["bestblockhash"],
                                                   verbosity=1)["time"]
            # if last block is older than 60 minutes something is probably wrong and we should wait
            if best_block_time < time.time() - 60 * 60:
                return False
        except Exception as e:
            raise ChainMonitorRpcError(f"ChainMonitor is_up_to_date: Could not get blockchain info: {e}")
        return True

    def get_tx_height(self, txid_hex: str) -> TxMinedInfo:
        pass

    def get_transaction(self, txid_hex: str) -> Optional[Transaction]:
        """getrawtransaction"""
        pass

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
