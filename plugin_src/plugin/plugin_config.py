import attr
import os
import sys
import electrum_ecc as ecc
from electrum_aionostr import Relay
from dotenv import load_dotenv
from .lnutil import hex_to_bytes, bytes_to_hex
from .json_db import StoredObject
from .cln_plugin import CLNPlugin
from .cln_logger import PluginLogger

class PluginConfig:

    """Simple configuration class for swap server"""
    def __init__(self, plugin: CLNPlugin):
        self.nostr_keypair = Keypair.from_private_key(plugin.derive_secret("NOSTRSECRET"))

        self.nostr_relays: [Relay] = []
        self.swapserver_fee_millionths: int = 10_000
        self.confirmation_speed_target_blocks: int = 10
        self.fallback_fee_sat_per_vb:int = 60
        self.logger = PluginLogger("swap-provider", plugin, level="DEBUG")
        self.logger.debug("Plugin logger initiated")


    @classmethod
    def from_env(cls, plugin: CLNPlugin) -> 'PluginConfig':
        """Load configuration from .env file or environment variables"""
        load_dotenv()
        config = PluginConfig(plugin)

        if relays := os.getenv("NOSTR_RELAYS"):
            config.nostr_relays.extend(Relay(url=url.strip()) for url in relays.split(","))
        else:
            raise Exception("No Nostr relays found. Set NOSTR_RELAYS as csv in env.")

        if fee_str := os.getenv("SWAP_FEE_PPM"):
            config.swapserver_fee_millionths = int(fee_str.strip())
        else:
            config.logger.warning(f"No swap fee in env. Using default value: {config.swapserver_fee_millionths}")

        if block_target := os.getenv("CONFIRMATION_TARGET_BLOCKS"):
            block_target = int(block_target.strip())
            if not 0 < block_target < 200:
               raise Exception("Invalid Block target. Use value between 0 and 200")
            config.confirmation_speed_target_blocks = block_target
        else:
            config.logger.warning(f"No CONFIRMATON_TARGET_BLOCKS found in env. "
                           f"Using default of {config.confirmation_speed_target_blocks}")

        if fallback_fee := os.getenv("FALLBACK_FEE_SATVB"):
            fallback_fee = int(fallback_fee.strip())
            if not 10 <= fallback_fee <= 300:
                raise Exception("FALLBACK_FEE_SATSVB is out of allowed range [10;300] ")
            else:
                config.fallback_fee_sat_per_vb = fallback_fee
        else:
            config.logger.warning(f"No FALLBACK_FEE_SATSVB set in env. Using default of {config.fallback_fee_sat_per_vb}")

        if log_level := os.getenv("PLUGIN_LOG_LEVEL"):
            config.logger = PluginLogger("swap-provider", plugin, level=log_level.strip())

        return config

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
