import math
import asyncio
from typing import Optional
from pyln.client import RpcError, LightningRpc

from .cln_logger import PluginLogger
from .plugin_config import PluginConfig
from .transaction import PartialTxOutput, PartialTransaction
from .utils import TxBroadcastError

class CLNChainWallet:
    def __init__(self, *, plugin_rpc: LightningRpc, config: PluginConfig, logger: PluginLogger):
        self.rpc = plugin_rpc
        self.config = config
        self.logger = logger
        self.logger.debug("CLNChainWallet initialized")

    def create_transaction(self, *, outputs_without_change: [PartialTxOutput], rbf: bool) -> Optional[PartialTransaction]:
        """Assembles a signed PSBT spending to the passed outputs from the CLN wallet. Automatically adds change output."""
        output_sum_sat: int = int(sum([o.value for o in outputs_without_change]))
        tx_core_weight = 42
        spk_weights: int = sum([(len(o.scriptpubkey) + 9) * 4 for o in outputs_without_change])
        startweight: int = tx_core_weight + spk_weights  # weight of the tx without any inputs (required for CLN)
        # get inpts from CLN wallet using fundpsbt rpc call
        try:
            fundpsbt_response = self.rpc.fundpsbt(satoshi=output_sum_sat,
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
        try:
           signed_psbt = self.rpc.signpsbt(complete_psbt_b64)["signed_psbt"]
        except Exception as e:
            self.logger.error("create_transaction failed to call signpsbt rpc: %s", e)
            return None

        signed_psbt = PartialTransaction().from_raw_psbt(signed_psbt)
        signed_psbt.finalize_psbt()

        return signed_psbt

    def broadcast_transaction(self, signed_psbt: PartialTransaction) -> None:
        """Broadcasts a signed transaction to the bitcoin network."""
        # psbt = PartialTransaction().from_tx(signed_tx)._serialize_as_base64()
        # broadcast psbt
        try:
            res = self.rpc.sendpsbt(signed_psbt._serialize_as_base64())
            self.logger.debug(f"broadcasted tx: {res}")
        except RpcError as e:
            raise TxBroadcastError(e)

    async def get_local_height(self, retries_30sec: int = 20) -> int:
        """Returns the current block height of the cln backend."""
        # we retry a couple of times as cln can be out of sync on new blocks or startup for some time
        while True:
            try:
                response = self.rpc.getinfo()
            except RpcError as e:
                raise e
            if ('warning_bitcoind_sync' in response
                or 'warning_lightningd_sync' in response
                or not 'blockheight' in response):
                self.logger.warning(f"get_local_height: cln backend is not synced, waiting, response: {response}")
                if retries_30sec <= 0:
                    raise Exception(f"get_local_height: cln backend is not synced, response: {response}")
                retries_30sec -= 1
                await asyncio.sleep(30)
            else:
                break
        blockheight = response['blockheight']
        if response['network'] == 'bitcoin':
            assert blockheight > 869000, "get_local_height: cln backend returns invalid height"
        return blockheight

    def get_chain_fee(self, *, size_vbyte: int) -> int:
        """Uses CLN lightning-feerates to get required fee for given size. Fees are very conservative due to bitcoin core
        fee estimation algorithm."""
        speed_target_blocks = self.config.confirmation_speed_target_blocks
        try:
            feerates = self.rpc.feerates("perkb")
            feerates = feerates['perkb']['estimates']
        except (RpcError, TimeoutError) as e:
            feerates = []
            self.logger.error(f"get_chain_fee failed to call feerates rpc: {e}. Using fallback feerate")

        prev_blockcount, feerate_pervb = 0, None
        for feerate in feerates:  # get feerate closest to confirmation target todo: we could also interpolate
            if speed_target_blocks >= feerate['blockcount'] > prev_blockcount:
                prev_blockcount = feerate['blockcount']
                feerate_pervb = feerate['smoothed_feerate'] / 1000
        if feerate_pervb is None:
            feerate_pervb = self.config.fallback_fee_sat_per_vb
            self.logger.warning(f"get_chain_fee using fallback fee rate of {feerate_pervb} sat/vbyte because result"
                                f" from cln rpc call was {feerates}")
        return math.ceil(feerate_pervb * size_vbyte)

    def get_receiving_address(self) -> str:
        """Returns a new receiving address from the CLN wallet."""
        try:
            address = self.rpc.newaddr()['bech32']
        except RpcError as e:
            raise Exception("get_receiving_address failed to call newaddr rpc: " + str(e))
        return address

    def balance_sat(self) -> int:
        try:
            outputs = self.rpc.listfunds()['outputs']
        except RpcError as e:
            raise Exception("CLNChainWallet: balance_sat failed to call listfunds rpc: " + str(e))
        balance = 0
        for output in outputs:
            if output['status'] == 'confirmed' and output['reserved'] == False:
                balance += output['amount_msat'] // 1000
        return int(balance * 0.9)
