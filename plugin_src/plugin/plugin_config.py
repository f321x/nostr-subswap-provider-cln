import attr
from .lnutil import hex_to_bytes, bytes_to_hex
from .json_db import StoredObject
from typing import Optional
from electrum_aionostr import Relay
from .cln_plugin import CLNPlugin
import electrum_ecc as ecc


class PluginConfig:
    """Simple configuration class for swap server, without electrum specific code"""
    def __init__(self, plugin: CLNPlugin):
        self.nostr_keypair = Keypair.from_private_key(plugin.derive_secret("NOSTRSECRET"))

        self.nostr_relays: Optional[Relay] = None
        self.swapserver_fee_millionths = None
        self.confirmation_speed_target_blocks = 10
        self.fallback_fee_sat_per_vb = 60
        self.log_level = "INFO"

    def from_env(self) -> 'PluginConfig':
        """todo: Load configuration from .env file or environment variables"""
        return self

    @property
    def cln_feerate_str(self) -> str:
        if self.confirmation_speed_target_blocks < 12:
            feerate = "urgent"
        elif self.confirmation_speed_target_blocks < 100:
            feerate = "normal"
        else:
            feerate = "slow"
        return feerate


@attr.s
class OnlyPubkeyKeypair(StoredObject):
    pubkey = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)


@attr.s
class Keypair(OnlyPubkeyKeypair):
    privkey = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)

    @classmethod
    def from_private_key(cls, privkey: bytes) -> 'Keypair':
        pubkey: bytes = ecc.ECPrivkey(privkey).get_public_key_bytes()
        return cls(pubkey=pubkey, privkey=privkey)



