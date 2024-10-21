import attr
from .lnutil import hex_to_bytes, bytes_to_hex
from .json_db import StoredObject
from typing import Optional
from electrum_aionostr import Relay


class PluginConfig:
    """Simple configuration class for swap server, without electrum specific code"""
    def __init__(self):
        self.nostr_keypair: Optional[Keypair] = None
        self.nostr_relays: Optional[Relay] = None
        self.swapserver_fee_millionths = None
        self.confirmation_speed_target_blocks = None
        pass

    def load_from_env(self) -> 'PluginConfig':
        """todo: Load configuration from .env file or environment variables"""
        return self


@attr.s
class OnlyPubkeyKeypair(StoredObject):
    pubkey = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)


@attr.s
class Keypair(OnlyPubkeyKeypair):
    privkey = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)



