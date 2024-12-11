from datetime import datetime
from typing import Optional, Callable, List
from .globals import set_plugin_logger_global


class PluginLogger:
    """Logger class that is compatible with the CLN logging standard (formatting and to stderr)"""
    def __init__(self, name: str, plugin_log_method: Callable[..., None], level: Optional[str] = "INFO"):
        self.level = level
        self.logger = plugin_log_method
        self.debug_buffer: List[str] = []  # Buffer to replay debug messages in higher log level if error occurs
        self.debug_buffer_size = 15
        set_plugin_logger_global(self)

    def debug(self, msg: str, override: bool = False):
        if self.is_enabled("DEBUG") or override:
            # DEBUG can be enabled in CLN but this way the plugin has its own debug mode and will always log if enabled
            msg = f"DEBUG: {msg}"
            self.logger(msg, level="info")
        else:
            self.append_to_buffer(msg)

    def info(self, msg: str):
        if self.is_enabled("INFO"):
            self.logger(msg, level="info")

    def warning(self, msg: str):
        if self.is_enabled("WARNING"):
            msg = f"WARNING: {msg}"  # CLN/plugin doesnt support WARN, so we use info
            self.logger(msg, level="info")

    def error(self, msg: str):
        self.replay_debug_buffer()  # Replay debug messages to make it easier to debug the error
        msg = f"ERROR: {msg}"  # CLN/plugin doesnt support ERROR, so we use info
        self.logger(msg, level="info")

    def change_level(self, level: str):
        self.level = level

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

    def append_to_buffer(self, msg: str) -> None:
        """Append a debug message to the buffer, delete the oldest if len is larger than max buffer size"""
        self.debug_buffer.append(f"buffered debug log from {datetime.now().isoformat()}: {msg}")
        if len(self.debug_buffer) > self.debug_buffer_size > 0:
            self.debug_buffer.pop(0)

    def replay_debug_buffer(self) -> None:
        """Replay all debug messages from the buffer"""
        self.debug("\nReplaying debug log buffer because of critical error:\n", override=True)
        for msg in self.debug_buffer:
            self.debug(msg, override=True)
        self.debug("\n", override=True)
        self.debug_buffer.clear()
