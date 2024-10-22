from pyln.client import RpcError
from .cln_plugin import CLNPlugin
from .plugin_config import PluginConfig
from .transaction import PartialTxOutput, PartialTransaction, Transaction


class CLNChainWallet:
    def __init__(self, *, plugin: CLNPlugin, config: PluginConfig):
        self.cln = plugin
        self.config = config
        # self.logger = config.logger
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


    def get_chain_fee(self, *, size_vbyte: int) -> int:
        """Uses CLN lightning-feerates to get required fee for given size"""
        speed_target_blocks = self.config.confirmation_speed_target_blocks
        feerates = self.cln.plugin.rpc.feerates("perkb")  # call should not take too long to pollute the async rt
        # ret val: {'warning_missing_feerates': 'Some fee estimates unavailable: bitcoind startup?',
        # 'perkb': {'min_acceptable': 1012, 'max_acceptable': 4294967295, 'floor': 1012, 'estimates': []}}

        # try:
        #     feerates["perkb"]["estimates"][0]
        return feerates


class TxBroadcastError(Exception):
    pass
