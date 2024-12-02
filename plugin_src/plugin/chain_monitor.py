import asyncio
from typing import Callable, Optional, List

from .cln_logger import PluginLogger
from .bitcoin_core_rpc import BitcoinCoreRPC, BitcoinRPCCredentials


class ChainMonitor(BitcoinCoreRPC):
    def __init__(self, logger: PluginLogger, bcore_rpc_credentials: BitcoinRPCCredentials) -> None:
        """Takes the bitcoin core rpc config from cln and uses bcore as chain backend"""
        super().__init__(logger, bcore_rpc_credentials)
        self.callbacks = {}
        self.monitoring_task = None

    async def run(self) -> None:
        """Run the chain monitor"""
        await super()._init()
        self.monitoring_task = asyncio.create_task(self.monitoring_loop())
        self._logger.debug("ChainMonitor: Running...")

    async def monitoring_loop(self) -> None:
        """Main monitoring loop, triggering callbacks on each new block"""
        last_height = await self.get_local_height()
        while True:
            await asyncio.sleep(10)
            try:
                blockheight = await self.get_local_height()
                if blockheight > last_height:
                    self._logger.debug(f"ChainMonitor: New blockheight: {blockheight}")
                    last_height = blockheight
                    await self.trigger_callbacks()
            except Exception as e:
                self._logger.error(f"ChainMonitor: Error in monitoring loop: {e}")

    async def trigger_callbacks(self) -> None:
        """Trigger all callbacks for monitored addresses"""
        for callback in list(self.callbacks.values()):
            try:
                await callback()
            except Exception as e:
                self._logger.error(f"ChainMonitor: Error in chain callback: {e}")

    def add_callback(self, lookup_address, callback: Callable) -> None:
        self._logger.debug(f"ChainMonitor: Adding callback for address {lookup_address}")
        self.callbacks[lookup_address] = callback

    def remove_callback(self, lookup_address) -> None:
        self._logger.debug(f"ChainMonitor: Removing callback for address {lookup_address}")
        self.callbacks.pop(lookup_address)
