from typing import Callable, Optional, Dict
from .plugin_config import PluginConfig
from .utils import TxMinedInfo
from .transaction import Transaction, TxOutpoint, PartialTxInput


class ChainMonitor:
    def __init__(self, config: PluginConfig):
        """Takes the bitcoin core rpc config from cln and uses bcore as chain backend"""
        self.monitored_addresses = set()
        self.callbacks = {}

    def add_callback(self, lookup_address, callback: Callable) -> None:
        self.monitored_addresses.add(lookup_address)
        self.callbacks[lookup_address] = callback

    def remove_callback(self, lookup_address) -> None:
        self.monitored_addresses.remove(lookup_address)
        self.callbacks.pop(lookup_address)

    def is_up_to_date(self) -> bool:
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
