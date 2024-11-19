from plugin_src.plugin.cln_logger import PluginLogger
from bitcoinrpc import BitcoinRPC, RPCError as BitcoinRPCError
import attr
from typing import Optional, Tuple

@attr.s(frozen=True, auto_attribs=True, kw_only=True)
class BitcoinRPCCredentials:
    """Credentials for Bitcoin Core RPC."""
    host: str
    port: int
    user: str
    password: str
    datadir: Optional[str] = None
    timeout: int = attr.ib(default=60, validator=attr.validators.instance_of(int))

    @classmethod
    def from_cln_config_dict(cls, cln_config: dict) -> "BitcoinRPCCredentials":
        """Load the credentials from the cln config dict fetched with lightning-listconfigs"""
        return cls(
            host=cln_config["bitcoin-rpcconnect"]["value_str"],
            port=cln_config["bitcoin-rpcport"]["value_int"],
            user=cln_config["bitcoin-rpcuser"]["value_str"],
            password=cln_config["bitcoin-rpcpassword"]["value_str"],
            datadir=cln_config.get("bitcoin-datadir", {}).get("value_str"),
            timeout=cln_config.get("bitcoin-rpcclienttimeout", {}).get("value_int", 60)
        )

    def __str__(self) -> str:
        """Return a string representation of the credentials for pretty debugging"""
        components = [
            f"Bitcoin RPC Credentials:",
            f"  URL: {self.url}",
            f"  User: {self.user}",
            f"  Password: {self.password}",
        ]
        if self.datadir:
            components.append(f"  Data Directory: {self.datadir}")
        components.append(f"  Timeout: {self.timeout}s")
        return '\n'.join(components)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def auth(self) -> Tuple[str, str]:
        """Auth format required for bitcoinrpc lib"""
        return self.user, self.password

class BitcoinCoreRPC:
    def __init__(self, logger: PluginLogger,
                        bcore_rpc_credentials: BitcoinRPCCredentials = None):
        self.iface = BitcoinRPC.from_config(url=bcore_rpc_credentials.url,
                                            auth=bcore_rpc_credentials.auth)
        self._logger = logger



