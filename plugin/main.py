#!/usr/bin/env python3
"""Core Lightning submarine swap provider plugin using the Electrum Nostr submarine swap protocol"""

from .cln_plugin import CLNPlugin
from .cln_chain import CLNChainWallet
from .cln_lightning import CLNLightning
from .plugin_config import PluginConfig
from .json_db import JsonDB
from .storage import Storage
from .submarine_swaps import SwapManager


def main():
    """main function starting the plugin"""

    # user config (from .env file or env)
    user_config = PluginConfig().load_from_env()

    # cln plugin
    plugin = CLNPlugin()
    cln_chain_wallet = CLNChainWallet(plugin=plugin, config=user_config)
    cln_lightning = CLNLightning(plugin=plugin, config=user_config)

    # data storage
    storage = Storage(".")  # storage path (cln .lightning dir)
    json_db = JsonDB(storage.read(), storage=storage)

    # swap manager
    swap_manager = SwapManager(wallet=cln_chain_wallet, lnworker=cln_lightning,
                               db=json_db, plugin_config=user_config)
    # swap_manager.main_loop()


if __name__ == "__main__":
    main()
