from .plugin_config import PluginConfig
from .transaction import PartialTxOutput, PartialTransaction, Transaction

class CLNChainWallet:
    def __init__(self):
        pass

    def create_transaction(self, *, outputs: [PartialTxOutput], rbf: bool) -> PartialTransaction:
        pass

    async def broadcast_transaction(self, tx: Transaction) -> None:
        pass

    async def get_chain_fee(self, *, size_vbyte: int, config: PluginConfig) -> int:
        """Uses CLN lightning-feerates to get required fee for given size"""
        # speed_target_blocks = config.confirmation_speed_target_blocks
        pass


class TxBroadcastError(Exception):
    pass
