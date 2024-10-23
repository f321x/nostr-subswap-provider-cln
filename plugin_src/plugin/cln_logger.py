from faulthandler import is_enabled
from typing import Optional
from .cln_plugin import CLNPlugin


class PluginLogger:
    """Logger class that is compatible with the CLN logging standard (formatting and to stderr)"""
    def __init__(self, name: str, plugin: CLNPlugin, level: Optional[str] = "INFO"):
        self.level = level
        self.logger = plugin.plugin.log

    def debug(self, msg: str):
        if self.is_enabled("DEBUG"):
            self.logger(msg, level="DEBUG")

    def info(self, msg: str):
        if self.is_enabled("INFO"):
            self.logger(msg, level="INFO")

    def warning(self, msg: str):
        if self.is_enabled("WARNING"):
            msg = f"WARNING: {msg}"  # plugin doesnt support WARN
            self.logger(msg, level="ERROR")

    def error(self, msg: str):
        if self.is_enabled("ERROR"):
            self.logger(msg, level="ERROR")


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

