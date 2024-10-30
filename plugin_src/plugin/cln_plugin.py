from pyln.client import Plugin
from pyln.client import LightningRpc
import asyncio

import sys
# def plugin_htlc_accepted_hook(onion, htlc, request, plugin, *args, **kwargs):
#     print("htlc_accepted hook called print", file=sys.stderr)
#     print(htlc, file=sys.stdout)
#     # self.logger.debug("htlc_accepted hook called")
#     return {"result": "continue"}


class CLNPlugin:
    def __init__(self):
        self.plugin = Plugin()
        # self.thread = asyncio.to_thread(self.plugin.run)  # the plugin is blocking to read stdin so we run it in a thread

    def __await__(self):
        async def _check_running():
            return self
            """Check if plugin.run() has returned in the thread"""
            task = asyncio.create_task(self.thread)  # temporarily create a task to check if the plugin is running
            await asyncio.sleep(5)  # sleep some time to leave the plugin time to do CLN handshake
            if task.done():
                raise Exception("Plugin not running")
            return self
        return _check_running().__await__()

    def derive_secret(self, derivation_str: str) -> bytes:
        """Derive a secret from CLN HSM secret (for use as Nostr secret)"""
        payload = {
            "string": derivation_str
        }
        secret_hex = self.plugin.rpc.call("makesecret", payload)["secret"]
        secret_bytes = bytes.fromhex(secret_hex)
        assert len(secret_bytes) == 32
        return secret_bytes

    # def _htlc_accepted(self, payload: dict):
    #     """Called when a new HTLC is accepted"""
        # do something with the payload
