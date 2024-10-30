from pyln.client import Plugin
import asyncio


class CLNPlugin:
    def __init__(self):
        self.plugin = Plugin()
        self.plugin.add_hook("htlc_hook", self._htlc_accepted, )
        self.thread = asyncio.to_thread(self.plugin.run)  # the plugin is blocking to read stdin so we run it in a thread

    def __await__(self):
        async def _check_running():
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

    def _htlc_accepted(self, payload: dict):
        """Called when a new HTLC is accepted"""
        # do something with the payload
