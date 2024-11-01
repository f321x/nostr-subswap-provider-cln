from typing import Callable
from plugin_src.plugin.plugin_config import PluginConfig


class ChainMonitor:
    def __init__(self, config: PluginConfig):
        self.monitored_addresses = set()
        self.callbacks = {}

    def add_callback(self, lookup_address, callback: Callable):
        self.monitored_addresses.add(lookup_address)
        self.callbacks[lookup_address] = callback

    def remove_callback(self, lookup_address):
        self.monitored_addresses.remove(lookup_address)
        self.callbacks.pop(lookup_address)
