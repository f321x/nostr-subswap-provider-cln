from typing import Callable
from pyln.client.plugin import JSONType
from pyln.client import Plugin
from threading import Event
import asyncio


class CLNPlugin:
    def __init__(self):
        self.plugin = Plugin()
        self.__htlc_hook = None
        self.__hook_ready = Event()
        self.plugin.add_hook("htlc_accepted", self.__htlc_hook_handler, background=True)
        # Create but don't start the thread yet
        self.__thread = None
        self.__task = None

    def __await__(self):
        async def __run():
            import sys
            self.__thread = asyncio.to_thread(self.plugin.run)
            self.__task = asyncio.create_task(self.__thread)
            await asyncio.sleep(5)
            if self.__task.done():
                raise Exception("Plugin failed to start.")
            return self

        return __run().__await__()

    def fetch_cln_configuration(self) -> dict:
        configuration = self.plugin.rpc.listconfigs()
        return configuration

    def __htlc_hook_handler(self, onion, htlc, request, plugin, *args, ** kwargs) -> None:
        """Dynamic htlc hook handler, calls the hook in self.htlc_hook"""
        if not self.__hook_ready.is_set():
            return request.set_result({"result": "continue"})
        return self.__htlc_hook(onion, htlc, request, plugin, *args, **kwargs)

    def set_htlc_hook(self, hook: Callable[..., JSONType]) -> None:
        self.__htlc_hook = hook
        self.__hook_ready.set()

    def derive_secret(self, derivation_str: str) -> bytes:
        """Derive a secret from CLN HSM secret (for use as Nostr secret)"""
        payload = {
            "string": derivation_str
        }
        secret_hex = self.plugin.rpc.call("makesecret", payload)["secret"]
        secret_bytes = bytes.fromhex(secret_hex)
        assert len(secret_bytes) == 32
        return secret_bytes
