from typing import Callable, Optional, Dict
from bitcoinrpc import BitcoinRPC

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

    def add_callback(self, lookup_address, callback: Callable) -> None:
        self.monitored_addresses.add(lookup_address)
        self.callbacks[lookup_address] = callback

    def remove_callback(self, lookup_address) -> None:
        self.monitored_addresses.remove(lookup_address)
        self.callbacks.pop(lookup_address)

    def is_up_to_date(self) -> bool:
        """We check if bcore is fully synced"""
        pass

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
