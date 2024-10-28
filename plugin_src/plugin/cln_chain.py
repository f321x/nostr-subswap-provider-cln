import math
from typing import Optional
from pyln.client import RpcError
from .cln_plugin import CLNPlugin
from .plugin_config import PluginConfig
from .globals import get_plugin_logger
from .transaction import PartialTxOutput, PartialTransaction, Transaction
from .utils import call_blocking_with_timeout


class CLNChainWallet:
    def __init__(self, *, plugin: CLNPlugin, config: PluginConfig):
        self.cln = plugin
        self.config = config
        self.logger = get_plugin_logger()
        self.logger.debug("CLNChainWallet initialized")

    async def create_transaction(self, *, outputs_without_change: [PartialTxOutput], rbf: bool) -> Optional[PartialTransaction]:
        """Assembles a signed PSBT spending to the passed outputs from the CLN wallet. Automatically adds change output."""
        output_sum_sat: int = int(sum([o.value for o in outputs_without_change]))
        tx_core_weight = 42
        spk_weights: int = sum([(len(o.scriptpubkey) + 9) * 4 for o in outputs_without_change])
        startweight: int = tx_core_weight + spk_weights  # weight of the tx without any inputs (required for CLN)
        # get inpts from CLN wallet using fundpsbt rpc call
        async with self.cln.stdinout_mutex:
            try:
                fundpsbt_response = self.cln.plugin.rpc.fundpsbt(satoshi=output_sum_sat,
                                                                feerate=self.config.cln_feerate_str,
                                                                startweight=startweight,
                                                                minconf=None,
                                                                reserve=6,
                                                                excess_as_change=True)
                raw_inputs_only_psbt = fundpsbt_response['psbt']
            except Exception as e:
                self.logger.error("create_transaction failed to call fundpsbt rpc: %s", e)
                return None

        # add outputs to inputs_only_psbt
        complete_psbt = PartialTransaction().from_raw_psbt(raw_inputs_only_psbt)
        complete_psbt.add_outputs(outputs_without_change)
        complete_psbt.set_rbf(rbf)
        complete_psbt_b64 = complete_psbt._serialize_as_base64()

        # sign psbt using CLN rpc call
        async with self.cln.stdinout_mutex:
            try:
               signed_psbt = self.cln.plugin.rpc.signpsbt(complete_psbt_b64)["signed_psbt"]
            except Exception as e:
                self.logger.error("create_transaction failed to call signpsbt rpc: %s", e)
                return None

        signed_psbt = PartialTransaction().from_raw_psbt(signed_psbt)
        signed_psbt.finalize_psbt()

        return signed_psbt


    async def broadcast_transaction(self, signed_psbt: PartialTransaction) -> None:
        """Broadcasts a signed transaction to the bitcoin network."""
        # psbt = PartialTransaction().from_tx(signed_tx)._serialize_as_base64()
        # broadcast psbt
        async with self.cln.stdinout_mutex:
            try:
                self.cln.plugin.rpc.sendpsbt(signed_psbt._serialize_as_base64())
            except RpcError as e:
                raise TxBroadcastError(e) from e


    async def get_local_height(self) -> int:
        """Returns the current block height of the cln backend."""
        async with self.cln.stdinout_mutex:
            try:
                response = await call_blocking_with_timeout(self.cln.plugin.rpc.getinfo, timeout=5)
            except (RpcError, TimeoutError) as e:
                raise e
        if 'warning_bitcoind_sync' or 'warning_lightningd_sync' or not 'blockheight' in response:
            raise Exception(f"get_local_height: cln backend is not synced, response: {response}")
        blockheight = response['blockheight']
        if response['network'] == 'bitcoin':
            assert blockheight > 860000, "get_local_height: cln backend returns invalid height"
        return blockheight

    async def get_chain_fee(self, *, size_vbyte: int) -> int:
        """Uses CLN lightning-feerates to get required fee for given size. Fees are very conservative due to bitcoin core
        fee estimation algorithm."""
        speed_target_blocks = self.config.confirmation_speed_target_blocks
        async with self.cln.stdinout_mutex:
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

    async def get_receiving_address(self) -> str:
        """Returns a new receiving address from the CLN wallet."""
        async with self.cln.stdinout_mutex:
            try:
                address = self.cln.plugin.rpc.newaddr()['bech32']
            except RpcError as e:
                raise Exception("get_receiving_address failed to call newaddr rpc: " + str(e))
        return address


class TxBroadcastError(Exception):
    pass
