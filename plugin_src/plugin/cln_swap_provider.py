import asyncio
import sys
from typing import Optional

from .cln_logger import PluginLogger
from .cln_plugin import CLNPlugin
from .cln_chain import CLNChainWallet
from .cln_lightning import CLNLightning
from .plugin_config import PluginConfig
from .chain_monitor import ChainMonitor
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

        # logging to cln logs
        self.logger = PluginLogger("swap-provider", self.plugin_handler.plugin.log)

        # user config (from .env file or env)
        self.config = PluginConfig.from_env(nostr_secret=self.plugin_handler.derive_secret("NOSTRSECRET"),
                                            logger=self.logger)

        # data storage using cln database trough rpc api
        storage = CLNStorage(db_string_writer=self.plugin_handler.plugin.rpc.datastore,
                             db_string_reader=self.plugin_handler.plugin.rpc.listdatastore,
                             logger=self.logger)
        self.json_db = JsonDB(s=storage.read(), storage=storage, logger=self.logger)


        # self.chain_monitor = ChainMonitor(config=self.config)

        # cln chain wallet
        # self.cln_chain_wallet = CLNChainWallet(plugin_rpc=self.plugin_handler.plugin.rpc,
        #                                        config=self.config,
        #                                        logger=self.logger)

        # cln lightning handlers
        self.cln_lightning = CLNLightning(plugin_instance=self.plugin_handler,
                                          config=self.config,
                                          db=self.json_db,
                                          logger=self.logger)
        await self.cln_lightning.run()

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

