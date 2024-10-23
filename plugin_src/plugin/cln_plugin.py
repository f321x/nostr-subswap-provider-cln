from pyln.client import Plugin
import asyncio

class CLNPlugin:
    def __init__(self):
        self.plugin = Plugin()
        # register methods in between
        self.thread = asyncio.to_thread(self.plugin.run)  # the plugin is blocking to read stdin so we run it in a thread

    async def check_running(self) -> 'CLNPlugin':
        task = asyncio.create_task(self.thread)  # temporarily create a task to check if the plugin is running
        await asyncio.sleep(5)  # sleep some time to leave the plugin time to do CLN handshake
        if task.done():
            raise Exception("Plugin not running")
        return self

    def derive_secret(self, derivation_str: str) -> bytes:
        """Derive a secret from CLN HSM secret (for use as Nostr secret)"""
        payload = {
            "string": derivation_str
        }
        secret_hex = self.plugin.rpc.call("makesecret", payload)["secret"]
        secret_bytes = bytes.fromhex(secret_hex)
        assert len(secret_bytes) == 32
        return secret_bytes
