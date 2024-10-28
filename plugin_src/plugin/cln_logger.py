import sys
import asyncio
from typing import Optional
from .cln_plugin import CLNPlugin
from .globals import set_plugin_logger_global


class PluginLogger:
    """Logger class that is compatible with the CLN logging standard (formatting and to stderr)"""
    def __init__(self, name: str, plugin: CLNPlugin, level: Optional[str] = "INFO"):
        self.level = level
        self.stdinout_mutex = plugin.stdinout_mutex
        self.logger = plugin.plugin.log
        self.log_queue = asyncio.Queue()
        set_plugin_logger_global(self)

    async def consume_messages(self):
        """Implement a log queue to have simple, sync log calls but still be able to use thes shared stdinout mutex"""
        while True:
            while not self.log_queue.empty():
                msg = await self.log_queue.get()
                async with self.stdinout_mutex:
                    self.logger(msg, level="info")
            await asyncio.sleep(0.1)

    def debug(self, msg: str):
        if self.is_enabled("DEBUG"):
            # DEBUG can be enabled in CLN but this way the plugin has its own debug mode and will always log if enabled
            msg = f"DEBUG: {msg}"
            self._put_on_output_queue(msg)

    def info(self, msg: str):
        if self.is_enabled("INFO"):
            self._put_on_output_queue(msg)

    def warning(self, msg: str):
        if self.is_enabled("WARNING"):
            msg = f"WARNING: {msg}"  # plugin doesnt support WARN
            self._put_on_output_queue(msg)

    def error(self, msg: str):
        if self.is_enabled("ERROR"):
            msg = f"ERROR: {msg}"  # plugin doesnt support ERROR
            self._put_on_output_queue(msg)

    def _put_on_output_queue(self, msg: str):
        try:
            self.log_queue.put_nowait(msg)
        except asyncio.QueueFull:
            print("Log queue full, dropping message:", msg, file=sys.stderr)

    def is_enabled(self, level: str) -> bool:
        """
        Check if the requested log level is equal or higher than the enabled level.
        Log levels hierarchy (from highest to lowest): DEBUG, INFO, WARNING, ERROR
        """
        levels = {
            "DEBUG": 0,
            "INFO": 1,
            "WARNING": 2,
            "ERROR": 3
        }

        # Get numeric values for comparison
        enabled_level = levels.get(self.level, 1)  # default to INFO if invalid level
        requested_level = levels.get(level, 1)  # default to INFO if invalid level

        # Return True if requested level is equal or higher (numerically lower or equal)
        return requested_level >= enabled_level

