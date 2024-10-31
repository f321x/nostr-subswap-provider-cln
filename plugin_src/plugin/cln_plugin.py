from typing import Callable
from typing import Optional, Any

from pyln.client.plugin import JSONType
from pyln.client import Plugin
from threading import Event
import asyncio


class CLNPlugin:
    def __init__(self):
        self.plugin = Plugin()
        self._htlc_hook = None  # type: Optional[Callable[..., JSONType]]
        self._hook_ready = Event()
        self._shutdown_handler = None
        self._shutdown_ready = Event()
        self.plugin.add_hook("htlc_accepted", self._htlc_hook_handler)
        self.plugin.add_subscription("shutdown", self._shutdown_event_handler)
        self._thread = asyncio.to_thread(self.plugin.run)  # the plugin is blocking to read stdin so we run it in a thread

    def __await__(self):
        async def _check_running():
            """Check if plugin.run() has returned in the thread, if so the handshake with CLN failed"""
            task = asyncio.create_task(self._thread)  # temporarily create a task to check if the plugin is running
            await asyncio.sleep(5)  # sleep some time to leave the plugin time to do CLN handshake
            if task.done():
                raise Exception("Plugin not running")
            return self
        return _check_running().__await__()

    def _htlc_hook_handler(self, onion, htlc, request, plugin, *args, ** kwargs) -> JSONType:
        """Dynamic htlc hook handler, calls the hook in self.htlc_hook"""
        if not self._hook_ready.is_set():
            return {"result": "continue"}
        return self._htlc_hook(onion, htlc, request, plugin, *args, **kwargs)

    def set_htlc_hook(self, hook: Callable[..., JSONType]) -> None:
        self._htlc_hook = hook
        self._hook_ready.set()

    def _shutdown_event_handler(self, **kwargs: dict[str, Any]) -> None:
        """Shutdown event handler, calls the hook in self.shutdown_handler"""
        if self._shutdown_ready.is_set():
            self._shutdown_handler()

    def set_shutdown_handler(self, handler: Callable[..., None]) -> None:
        self._shutdown_handler = handler
        self._shutdown_ready.set()

    def derive_secret(self, derivation_str: str) -> bytes:
        """Derive a secret from CLN HSM secret (for use as Nostr secret)"""
        payload = {
            "string": derivation_str
        }
        secret_hex = self.plugin.rpc.call("makesecret", payload)["secret"]
        secret_bytes = bytes.fromhex(secret_hex)
        assert len(secret_bytes) == 32
        return secret_bytes
