import time
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
        self.__buffered_htlcs = []  # CLN replays htlcs, we buffer them until the hook is set so none get missed
        self.plugin.add_hook("htlc_accepted", self.__htlc_hook_handler, background=True)
        # Create but don't start the thread yet
        self.__task = None

    def __await__(self):
        async def __run():
            self.__task = asyncio.create_task(asyncio.to_thread(self.plugin.run))
            await asyncio.wait_for(self.__await_rpc(), timeout=50)
            return self
        return __run().__await__()

    async def __await_rpc(self):
        """Wait for the rpc to be ready, this will take quite different amounts of time depending on the environment"""
        while True:
            if self.plugin.rpc is not None:
                return
            if self.__task.done():
                raise Exception("Plugin failed to start, thread returned")
            await asyncio.sleep(0.5)

    def fetch_cln_configuration(self) -> dict:
        configuration = self.plugin.rpc.listconfigs()
        return configuration["configs"]

    def __htlc_hook_handler(self, onion, htlc, request, plugin, *args, ** kwargs) -> None:
        """Dynamic htlc hook handler, calls the hook in self.htlc_hook"""
        if not self.__hook_ready.is_set():
            self.__buffered_htlcs.append({
                'onion': onion,
                'htlc': htlc,
                'request': request,
                'plugin': plugin,
                'args': args,
                'kwargs': kwargs
            })
            return
        return self.__htlc_hook(onion, htlc, request, plugin, *args, **kwargs)

    def __replay_buffered_htlcs(self):
        """Replay the htlcs we buffered while the hook was not ready"""
        if len(self.__buffered_htlcs) == 0:
            return
        self.plugin.log(f"Replaying {len(self.__buffered_htlcs)} buffered htlcs", level="debug")
        for htlc in self.__buffered_htlcs:
            self.__htlc_hook(htlc['onion'],
                             htlc['htlc'],
                             htlc['request'],
                             htlc['plugin'],
                             *htlc['args'],
                             **htlc['kwargs'])
        self.__buffered_htlcs = []

    def set_htlc_hook(self, hook: Callable[..., JSONType]) -> None:
        self.__htlc_hook = hook
        self.__hook_ready.set()
        self.__replay_buffered_htlcs()

    def derive_secret(self, derivation_str: str) -> bytes:
        """Derive a secret from CLN HSM secret (for use as Nostr secret)"""
        payload = {
            "string": derivation_str
        }
        secret_hex = self.plugin.rpc.call("makesecret", payload)["secret"]
        secret_bytes = bytes.fromhex(secret_hex)
        assert len(secret_bytes) == 32
        return secret_bytes
