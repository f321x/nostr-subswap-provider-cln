from .transaction import PartialTxOutput, PartialTransaction, Transaction

class CLNChainWallet:
    def __init__(self):
        pass

    def create_transaction(self, *, outputs: [PartialTxOutput], rbf: bool) -> PartialTransaction:
        pass

    async def broadcast_transaction(self, tx: Transaction) -> None:
        pass


class TxBroadcastError(Exception):
    pass
