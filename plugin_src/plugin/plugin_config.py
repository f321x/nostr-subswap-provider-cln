import attr
import os
import electrum_ecc as ecc
from electrum_aionostr import Relay
from dotenv import load_dotenv
from typing import Optional

from .cln_plugin import CLNPlugin
from .lnutil import hex_to_bytes, bytes_to_hex
from .json_db import StoredObject
from .cln_logger import PluginLogger
from . import constants
from .constants import AbstractNet, BitcoinMainnet, BitcoinTestnet, BitcoinSignet, BitcoinRegtest
from .bitcoin_core_rpc import BitcoinRPCCredentials


class PluginConfig:

    """Simple configuration class for swap server"""
    def __init__(self, *, nostr_secret: bytes, cln_configuration: dict, logger: PluginLogger):
        self.nostr_keypair = Keypair.from_private_key(nostr_secret) # plugin.derive_secret("NOSTRSECRET"))
        self.cln_config: dict = cln_configuration
        self.bcore_rpc_credentials = BitcoinRPCCredentials.from_cln_config_dict(cln_configuration)
        self.network = self.__parse_network_type(cln_configuration["network"]["value_str"])  # type: Optional[AbstractNet]
        self.nostr_relays: [Relay] = []
        self.swapserver_fee_millionths: int = 10_000
        self.confirmation_speed_target_blocks: int = 10
        self.fallback_fee_sat_per_vb:int = 60
        self.logger = logger  # PluginLogger("swap-provider", plugin, level="DEBUG")

    @classmethod
    def from_cln_and_env(cls, *, cln_plugin_handler: CLNPlugin, logger: PluginLogger) -> 'PluginConfig':
        """Load configuration from .env file or environment variables"""
        load_dotenv()
        config = PluginConfig(nostr_secret=cln_plugin_handler.derive_secret("NOSTRSECRET"),
                            cln_configuration=cln_plugin_handler.fetch_cln_configuration(),
                            logger=logger)
        constants.net = config.network
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
            config.logger.change_level(log_level.strip())

        config.logger.debug(f"Loaded configuration: {config}")
        return config

    @staticmethod
    def __parse_network_type(network_type: str) -> AbstractNet:
        if network_type == "mainnet":
            return BitcoinMainnet()
        elif network_type == "testnet":
            return BitcoinTestnet()
        elif network_type == "signet":
            return BitcoinSignet()
        elif network_type == "regtest":
            return BitcoinRegtest()
        else:
            raise Exception(f"Invalid network type: {network_type}")

    @property
    def cln_feerate_str(self) -> str:
        if self.confirmation_speed_target_blocks < 12:
            feerate = "urgent"
        elif self.confirmation_speed_target_blocks < 100:
            feerate = "normal"
        else:
            feerate = "slow"
        return feerate

    def __str__(self):
        relays = [relay.url for relay in self.nostr_relays]
        return f"nostr_pubkey={self.nostr_keypair.pubkey.hex()}, " \
               f"nostr_relays={relays}, " \
               f"swapserver_fee_millionths={self.swapserver_fee_millionths}, " \
               f"confirmation_speed_target_blocks={self.confirmation_speed_target_blocks}, " \
               f"fallback_fee_sat_per_vb={self.fallback_fee_sat_per_vb})"


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
