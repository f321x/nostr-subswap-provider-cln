import asyncio
from typing import Callable, Optional, List

from .cln_logger import PluginLogger
from .bitcoin_core_rpc import BitcoinCoreRPC, BitcoinRPCCredentials


class ChainMonitor(BitcoinCoreRPC):
    def __init__(self, logger: PluginLogger, bcore_rpc_credentials: BitcoinRPCCredentials) -> None:
        """Takes the bitcoin core rpc config from cln and uses bcore as chain backend"""
        super().__init__(logger, bcore_rpc_credentials)
        self.callbacks = {}
        self.monitoring_task = None

    async def run(self) -> None:
        """Run the chain monitor"""
        await super()._init()
        self.monitoring_task = asyncio.create_task(self.monitoring_loop())
        self._logger.debug("ChainMonitor: Running...")

    async def monitoring_loop(self) -> None:
        """Main monitoring loop, triggering callbacks on each new block"""
        last_height = await self.get_local_height()
        while True:
            await asyncio.sleep(10)
            try:
                blockheight = await self.get_local_height()
                if blockheight > last_height:
                    self._logger.debug(f"ChainMonitor: New blockheight: {blockheight}")
                    last_height = blockheight
                    await self.trigger_callbacks()
            except Exception as e:
                self._logger.error(f"ChainMonitor: Error in monitoring loop: {e}")

    async def trigger_callbacks(self) -> None:
        """Trigger all callbacks for monitored addresses"""
        for callback in self.callbacks.values():
            try:
                await callback()
            except Exception as e:
                self._logger.error(f"ChainMonitor: Error in chain callback: {e}")

    def add_callback(self, lookup_address, callback: Callable) -> None:
        self._logger.debug(f"ChainMonitor: Adding callback for address {lookup_address}")
        self.callbacks[lookup_address] = callback

    def remove_callback(self, lookup_address) -> None:
        self._logger.debug(f"ChainMonitor: Removing callback for address {lookup_address}")
        self.callbacks.pop(lookup_address)

    # async def get_addr_outputs(self, address: str) -> List[PartialTxInput]:
    #     """Getting utxos for the address in form of a PartialTxInput. The utxo will be marked spent
    #     if it has already been spent again"""
    #     funding_inputs: List[PartialTxInput] = []
    #     try:
    #         received = await self.iface.acall(method="listreceivedbyaddress",
    #                                           params=[1, True, True, address])
    #     except BitcoinRPCError as e:
    #         raise ChainMonitorRpcError(f"ChainMonitor: get_addr_outputs call for {address} failed: {e}")
    #     if len(received) == 0:
    #         raise UnknownAddressError(f"ChainMonitor: get_addr_outputs: Address {address} hasn't been imported before")
    #     received_txids = received[0]['txids']  # all txids of transactions that spent to 'address'
    #     for txid in received_txids:
    #         utxo = await self._get_partial_txin(txid, address)
    #         # TODO:
    #
    # async def _get_partial_txin(self, received_txid_hex: str, address: str) -> PartialTxInput:
    #     received_tx = await self.get_transaction(received_txid_hex)
    #     tx_mined_info = await self.get_tx_height(received_txid_hex)
    #     if received_tx is None:
    #         raise ChainMonitorRpcError(f"ChainMonitor: _get_partial_txin: Could not find transaction {received_txid_hex}")
    #     # we search the index of the output of the funding tx spending to the funding address
    #     for index, output in enumerate(received_tx.outputs):
    #         if output.address == address:
    #             break
    #     else:  # this shouldn't happen
    #         raise ChainMonitorRpcError(f"ChainMonitor: _get_partial_txin: "
    #                                    f"Could not find output for address {address} in transaction {received_txid_hex}")
    #
    #     future_prevout = TxOutpoint(txid=bytes.fromhex(received_txid_hex), out_idx=index)
    #     is_coinbase = True if len(received_tx.inputs()) == 0 else False
    #     # getting partialTxInput
    #     utxo = PartialTxInput(prevout=future_prevout, is_coinbase_output=is_coinbase)
    #     utxo._trusted_address = address
    #     utxo._trusted_value_sats = output.value
    #     utxo.block_height = tx_mined_info.height
    #     utxo.block_txpos = None # we don't need this for swaps
    #     # TODO: spent checking will happen in a separate function
    #     utxo.spent_height = None
    #     utxo.spent_txid = None
    #     return utxo
    #
    # async def update_spends_in_txin(self, txin: PartialTxInput) -> None:
    #     pass
    #     # we check if the utxo exists in the utxoset


class UnknownAddressError(Exception):
    pass
