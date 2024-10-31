import asyncio
import sys
from typing import Optional

from .cln_logger import PluginLogger
from .cln_plugin import CLNPlugin
from .cln_chain import CLNChainWallet
from .cln_lightning import CLNLightning
from .plugin_config import PluginConfig
from .cln_storage import CLNStorage
from .json_db import JsonDB
from .submarine_swaps import SwapManager


class CLNSwapProvider:
    def __init__(
        self,
        plugin_handler: Optional[CLNPlugin] = None,
        logger: Optional[PluginLogger] = None,
        config: Optional[PluginConfig] = None,
        json_db: Optional[JsonDB] = None,
        cln_chain_wallet: Optional[CLNChainWallet] = None,
        cln_lightning: Optional[CLNLightning] = None,
        swap_manager: Optional[SwapManager] = None
    ):
        if plugin_handler is not None:
            plugin_handler.set_shutdown_handler(self.shutdown)
        self.plugin_handler = plugin_handler
        self.logger = logger
        self.config = config
        self.json_db = json_db
        self.cln_chain_wallet = cln_chain_wallet
        self.cln_lightning = cln_lightning
        self.swap_manager = swap_manager

    async def initialize(self):
        # cln plugin handler
        self.plugin_handler = await CLNPlugin()
        self.plugin_handler.set_shutdown_handler(self.shutdown)

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
        # self.cln_chain_wallet = CLNChainWallet(plugin_rpc=self.plugin_handler.plugin.rpc,
        #                                        config=self.config,
        #                                        logger=self.logger)

        # cln lightning handlers
        self.cln_lightning = CLNLightning(plugin_instance=self.plugin_handler,
                                          config=self.config,
                                          db=self.json_db,
                                          logger=self.logger)

        # swap manager
        # self.swap_manager = SwapManager(wallet=self.cln_chain_wallet,
        #                                 lnworker=self.cln_lightning,
        #                                 db=self.json_db,
        #                                 plugin_config=self.config,
        #                                 logger=self.logger)


    async def run(self):
        if not self.is_initialized:
            await self.initialize()
        await asyncio.sleep(100000000)
        await self.swap_manager.main_loop()
        raise Exception("CLNSwapProvider main loop exited unexpectedly")

    def shutdown(self):
        """Shutdown handler called by CLN on shutdown"""
        self.logger.info("Shutting down CLNSwapProvider")
        if self.swap_manager is not None:
            asyncio.get_event_loop().run_until_complete(self.swap_manager.stop())
        if self.json_db is not None and len(self.json_db.pending_changes) > 0:
            self.json_db.write()
        sys.exit(0)

    @property
    def is_initialized(self) -> bool:
        if (self.plugin_handler
            and self.logger
            and self.config
            and self.json_db
            and self.cln_chain_wallet
            and self.cln_lightning
            and self.swap_manager):
            return True
        return False

