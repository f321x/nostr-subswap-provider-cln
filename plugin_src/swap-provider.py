#!/usr/bin/env python3
"""
Core Lightning submarine swap provider plugin using the Electrum Nostr submarine swap protocol.
cp plugin_src/* in the CLN plugin dir, or set plugin=/path/to/swap-provider.py in the CLN config to run.
"""

from plugin.cln_plugin import CLNPlugin
from plugin.cln_chain import CLNChainWallet
from plugin.plugin_config import PluginConfig
import sys
import asyncio


async def main():
    """main function starting the plugin"""

    # user config (from .env file or env)
    user_config = PluginConfig().load_from_env()

    # cln plugin
    plugin = await CLNPlugin().check_running()
    cln_chain_wallet = CLNChainWallet(plugin=plugin, config=user_config)
    print(f"PLUGIN FEERATE: {cln_chain_wallet.get_chain_fee(size_vbyte=100)}", file=sys.stderr)
    # cln_lightning = CLNLightning(plugin=plugin, config=user_config)

    # data storage
    # storage = Storage(".")  # storage path (cln .lightning dir)
    # json_db = JsonDB(storage.read(), storage=storage)

    # swap manager
    # swap_manager = SwapManager(wallet=cln_chain_wallet, lnworker=cln_lightning,
    #                            db=json_db, plugin_config=user_config)
    # swap_manager.main_loop()


if __name__ == "__main__":
    asyncio.run(main())
