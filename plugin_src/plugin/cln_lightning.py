from .cln_plugin import CLNPlugin
from .plugin_config import PluginConfig
from .utils import call_blocking_with_timeout

class CLNLightning:
    def __init__(self, *, plugin: CLNPlugin, config: PluginConfig):
        self.plugin = plugin
        self.config = config
        self.logger = config.logger
        self.logger.debug("CLNLightning initialized")

    def register_hold_invoice(self, *, payment_hash: bytes, callback: callable):
        pass

    async def pay_invoice(self, *, bolt11: str, attempts: int) -> (bool, str):  # -> (success, log)
        retry_for = attempts * 45 if attempts > 1 else 60  # CLN automatically retries for the given amount of time
        async with self.plugin.stdinout_mutex:
            try:
                result = await call_blocking_with_timeout(self.plugin.plugin.rpc.pay(bolt11=bolt11, retry_for=retry_for),
                                                    timeout=retry_for + 30)
            except Exception as e:
                return False, "pay_invoice call to CLN failed: " + str(e)

        if 'payment_preimage' in result and result['payment_preimage'] and result['status'] == 'complete':
            return True, result['payment_preimage']
        return False, result




