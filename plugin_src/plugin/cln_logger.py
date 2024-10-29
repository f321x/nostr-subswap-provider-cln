from typing import Optional
from .cln_plugin import CLNPlugin
from .globals import set_plugin_logger_global


class PluginLogger:
    """Logger class that is compatible with the CLN logging standard (formatting and to stderr)"""
    def __init__(self, name: str, plugin: CLNPlugin, level: Optional[str] = "INFO"):
        self.level = level
        self.logger = plugin.plugin.log
        set_plugin_logger_global(self)

    def debug(self, msg: str):
        if self.is_enabled("DEBUG"):
            # DEBUG can be enabled in CLN but this way the plugin has its own debug mode and will always log if enabled
            msg = f"DEBUG: {msg}"
            self.logger(msg, level="info")

    def info(self, msg: str):
        if self.is_enabled("INFO"):
            self.logger(msg, level="info")

    def warning(self, msg: str):
        if self.is_enabled("WARNING"):
            msg = f"WARNING: {msg}"  # CLN/plugin doesnt support WARN
            self.logger(msg, level="info")

    def error(self, msg: str):
        if self.is_enabled("ERROR"):
            msg = f"ERROR: {msg}"  # CLN/plugin doesnt support ERROR
            self.logger(msg, level="info")

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

