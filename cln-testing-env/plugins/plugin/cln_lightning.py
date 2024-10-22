from .cln_plugin import CLNPlugin
from .plugin_config import PluginConfig

class CLNLightning:
    def __init__(self, *, plugin: CLNPlugin, config: PluginConfig):
        self.plugin = plugin
        self.config = config
        pass

    def register_hold_invoice(self, *, payment_hash: bytes, callback: callable):
        pass

    async def pay_invoice(self, *, bolt11: str, attempts: int) -> (bool, str):  # -> (success, log)
        pass
