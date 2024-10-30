import asyncio
from typing import Optional, Any
from pyln.client import Plugin
from .cln_logger import PluginLogger
from .cln_plugin import CLNPlugin
from .cln_chain import CLNChainWallet
from .cln_lightning import CLNLightning
from .plugin_config import PluginConfig
from .cln_storage import CLNStorage
from .json_db import JsonDB
from .submarine_swaps import SwapManager


# class CLNSwapProvider:
#     def __init__(
#         self,
#         logger: Optional[PluginLogger] = None,
#         config: Optional[PluginConfig] = None,
#         json_db: Optional[JsonDB] = None,
#         cln_chain_wallet: Optional[CLNChainWallet] = None,
#         cln_lightning: Optional[CLNLightning] = None,
#         swap_manager: Optional[SwapManager] = None
#     ):
#         self.
#         self.logger = logger
#         self.config = config
#         self.json_db = json_db
#         self.cln_chain_wallet = cln_chain_wallet
#         self.cln_lightning = cln_lightning
#         self.swap_manager = swap_manager
plugin_handler = CLNPlugin()
config = None
json_db = None
cln_chain_wallet = None
cln_lightning = None

@plugin_handler.plugin.init()
def init(
    options: dict[str, Any],
    configuration: dict[str, Any],
    plugin: Plugin,
    **kwargs: dict[str, Any],
) -> None:
    # cln plugin handler
    # self.plugin_handler = await CLNPlugin()
    global plugin_handler
    global config
    global json_db
    global cln_chain_wallet
    global cln_lightning

    # logging to cln logs
    logger = PluginLogger("swap-provider", plugin.log)

    # user config (from .env file or env)
    config = PluginConfig.from_env(nostr_secret=plugin_handler.derive_secret("NOSTRSECRET"),
                                        logger=logger)

    # data storage using cln database trough rpc api
    storage = CLNStorage(db_string_writer=plugin.rpc.datastore,
                         db_string_reader=plugin.rpc.listdatastore)
    json_db = JsonDB(s=storage.read(), storage=storage, logger=logger)

    # cln chain wallet
    cln_chain_wallet = CLNChainWallet(plugin_rpc=plugin.rpc,
                                           config=config,
                                           logger=logger)

    # cln lightning handlers
    cln_lightning = CLNLightning(plugin_instance=plugin_handler,
                                      config=config,
                                      db=json_db,
                                      logger=logger)

        # swap manager
        # self.swap_manager = SwapManager(wallet=self.cln_chain_wallet,
        #                                 lnworker=self.cln_lightning,
        #                                 db=self.json_db,
        #                                 plugin_config=self.config,
        #                                 logger=self.logger)

async def run():
    global plugin_handler
    global config
    global json_db
    global cln_chain_wallet
    global cln_lightning
    await asyncio.to_thread(plugin_handler.plugin.run)

    # async def run(self):
    #     if not self.is_initialized:
    #         await self.initialize()
    #     await asyncio.sleep(100000000)  # testing
    #     await self.swap_manager.main_loop()
    #     raise Exception("CLNSwapProvider main loop exited unexpectedly")
    #
    # @property
    # def is_initialized(self) -> bool:
    #     if (self.plugin_handler
    #         and self.logger
    #         and self.config
    #         and self.json_db
    #         and self.cln_chain_wallet
    #         and self.cln_lightning
    #         and self.swap_manager):
    #         return True
    #     return False
    #
