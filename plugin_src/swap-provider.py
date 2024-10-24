#!/usr/bin/env python3
"""
Core Lightning submarine swap provider plugin using the Electrum Nostr submarine swap protocol.
To run install requirements (pip install -r requirements.txt), then
cp plugin_src/* in the CLN plugin dir, or set plugin=/path/to/swap-provider.py in the CLN config to run.
"""

import asyncio
import sys
from plugin.cln_plugin import CLNPlugin
from plugin.cln_chain import CLNChainWallet
from plugin.cln_lightning import CLNLightning
from plugin.plugin_config import PluginConfig
# from plugin.storage import Storage
# from plugin.json_db import JsonDB
# from plugin.submarine_swaps import SwapManager


async def main():
    """main function starting the plugin"""
    try:
        # cln plugin (also initializes logging to stderr)
        plugin = await CLNPlugin()

        # user config (from .env file or env)
        user_config = PluginConfig.from_env(plugin)
        asyncio.create_task(user_config.logger.consume_messages())  # log message consumer for CLN logging

        cln_chain_wallet = CLNChainWallet(plugin=plugin, config=user_config)
        cln_lightning = CLNLightning(plugin=plugin, config=user_config)

        # data storage
        # storage = Storage(".")  # storage path (cln .lightning dir)
        # json_db = JsonDB(storage.read(), storage=storage)

        # swap manager
        # swap_manager = SwapManager(wallet=cln_chain_wallet, lnworker=cln_lightning,
        #                            db=json_db, plugin_config=user_config)
        # await swap_manager.main_loop()
    except Exception as e:
        print("swap-provider crashed:", e, file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
