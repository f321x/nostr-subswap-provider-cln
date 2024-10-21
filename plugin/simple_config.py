import attr
from .lnutil import hex_to_bytes, bytes_to_hex
from .json_db import StoredObject
from typing import Optional
from electrum_aionostr import Relay


class Config:
    """Simple configuration class for swap server, without electrum specific code"""
    def __init__(self):
        self.nostr_keypair: Optional[Keypair] = None
        self.nostr_relays: Optional[Relay] = None
        pass

    def load_from_env(self):
        """Load configuration from .env file or environment variables"""
        pass


@attr.s
class OnlyPubkeyKeypair(StoredObject):
    pubkey = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)


@attr.s
class Keypair(OnlyPubkeyKeypair):
    privkey = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)



