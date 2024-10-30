from typing import Optional

from .cln_logger import PluginLogger
from .cln_plugin import CLNPlugin
from .cln_chain import CLNChainWallet
from .cln_lightning import CLNLightning
from .globals import plugin_logger
from .plugin_config import PluginConfig
from .cln_storage import CLNStorage
from .json_db import JsonDB
from .submarine_swaps import SwapManager


# from plugin.submarine_swaps import SwapManager

class CLNSwapProvider:
    def __init__(self):
        self.plugin_handler: Optional[CLNPlugin] = None
        self.logger: Optional[PluginLogger] = None
        self.config: Optional[PluginConfig] = None
        self.json_db: Optional[JsonDB] = None
        self.cln_chain_wallet: Optional[CLNChainWallet] = None
        self.cln_lightning: Optional[CLNLightning] = None
        self.swap_manager: Optional[SwapManager] = None
        self.is_initialized: bool = False

    async def initialize(self):
        # cln plugin handler
        self.plugin_handler = await CLNPlugin()

        # logging to cln logs
        self.logger = PluginLogger("swap-provider", self.plugin_handler.plugin.log)

        # user config (from .env file or env)
        self.config = PluginConfig.from_env(nostr_secret=self.plugin_handler.derive_secret("NOSTRSECRET"),
                                            logger=self.logger)

        # data storage using cln database trough rpc api
        storage = CLNStorage(db_string_writer=self.plugin_handler.plugin.rpc.datastore,
                             db_string_reader=self.plugin_handler.plugin.rpc.listdatastore)
        self.json_db = JsonDB(s=storage.read(), storage=storage, logger=self.logger)

        # cln chain wallet
        self.cln_chain_wallet = CLNChainWallet(plugin_rpc=self.plugin_handler.plugin.rpc,
                                               config=self.config,
                                               logger=self.logger)

        # cln lightning handlers
        self.cln_lightning = CLNLightning(plugin_rpc=self.plugin_handler.plugin.rpc,
                                          config=self.config,
                                          db=self.json_db,
                                          logger=self.logger)

        # swap manager
        self.swap_manager = SwapManager(wallet=self.cln_chain_wallet,
                                        lnworker=self.cln_lightning,
                                        db=self.json_db,
                                        plugin_config=self.config,
                                        logger=self.logger)

        self.is_initialized = True

    async def run(self):
        if not self.is_initialized:
            await self.initialize()
        await self.swap_manager.main_loop()
        raise Exception("CLNSwapProvider main loop exited unexpectedly")

