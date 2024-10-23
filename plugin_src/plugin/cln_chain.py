import logging
import math
from pyln.client import RpcError
from .cln_plugin import CLNPlugin
from .plugin_config import PluginConfig
from .transaction import PartialTxOutput, PartialTransaction, Transaction
from .utils import call_blocking_with_timeout


class CLNChainWallet:
    def __init__(self, *, plugin: CLNPlugin, config: PluginConfig):
        self.cln = plugin
        self.config = config
        self.logger = logging.getLogger(__name__)
        pass

    def create_transaction(self, *, outputs: [PartialTxOutput], rbf: bool) -> PartialTransaction:
        pass

    async def broadcast_transaction(self, signed_tx: Transaction) -> None:
        psbt = PartialTransaction().from_tx(signed_tx)._serialize_as_base64()
        # broadcast psbt
        try:
            self.cln.plugin.rpc.sendpsbt(psbt)
        except RpcError as e:
            raise TxBroadcastError(e) from e


    async def get_chain_fee(self, *, size_vbyte: int) -> int:
        """Uses CLN lightning-feerates to get required fee for given size. Fees are very conservative due to bitcoin core
        fee estimation algorithm."""
        speed_target_blocks = self.config.confirmation_speed_target_blocks
        try:
            feerates = await call_blocking_with_timeout(self.cln.plugin.rpc.feerates, "perkb", timeout=5)
            feerates = feerates['perkb']['estimates']
        except (RpcError, TimeoutError) as e:
            feerates = []
            self.logger.error("get_chain_fee failed to call feerates rpc: %s. Using fallback feerate", e)

        prev_blockcount, feerate_pervb = 0, None
        for feerate in feerates:  # get feerate closest to confirmation target
            if speed_target_blocks >= feerate['blockcount'] > prev_blockcount:
                prev_blockcount = feerate['blockcount']
                feerate_pervb = feerate['smoothed_feerate'] / 1000
        if feerate_pervb is None:
            feerate_pervb = self.config.fallback_fee_sat_per_vb
            self.logger.warning("get_chain_fee using fallback fee rate of %s sat/vbyte", feerate_pervb)
        return math.ceil(feerate_pervb * size_vbyte)


class TxBroadcastError(Exception):
    pass
