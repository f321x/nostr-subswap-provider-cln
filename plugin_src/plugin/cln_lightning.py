import os
from typing import NamedTuple, Optional
from enum import IntEnum
import threading

from .cln_storage import CLNStorage
from .crypto import sha256
from .invoices import PR_UNPAID, PR_PAID
from .cln_plugin import CLNPlugin
from .json_db import JsonDB
from .plugin_config import PluginConfig
from .utils import call_blocking_with_timeout


class PaymentInfo(NamedTuple):
    payment_hash: bytes
    amount_msat: Optional[int]
    direction: int
    status: int

class Direction(IntEnum):
    SENT = -1     # in the context of HTLCs: "offered" HTLCs
    RECEIVED = 1  # in the context of HTLCs: "received" HTLCs

SAVED_PR_STATUS = [PR_PAID, PR_UNPAID] # status that are persisted
SENT = Direction.SENT
RECEIVED = Direction.RECEIVED

class CLNLightning:
    def __init__(self, *, plugin: CLNPlugin, config: PluginConfig, db: JsonDB):
        self.plugin = plugin
        self.config = config
        self.db = db
        self.logger = config.logger
        self.lock = threading.RLock()
        self.payment_info = self.db.get_dict('lightning_payments')  # RHASH -> amount, direction, is_paid
        self.preimages = self.db.get_dict('lightning_preimages')  # RHASH -> preimage
        self.logger.debug("CLNLightning initialized")

    def register_hold_invoice(self, *, payment_hash: bytes, callback: callable):
        pass

    async def pay_invoice(self, *, bolt11: str, attempts: int) -> (bool, str):  # -> (success, log)
        retry_for = attempts * 45 if attempts > 1 else 60  # CLN automatically retries for the given amount of time
        async with self.plugin.stdinout_mutex:
            try:
                result = await call_blocking_with_timeout(self.plugin.plugin.rpc.pay(bolt11=bolt11, retry_for=retry_for),
                                                    timeout=retry_for + 30)
            except Exception as e:
                return False, "pay_invoice call to CLN failed: " + str(e)

        # check if the payment was successful, currently we assume it failed if it's not "complete"
        if 'payment_preimage' in result and result['payment_preimage'] and result['status'] == 'complete':
            return True, result['payment_preimage']
        return False, result


    async def create_payment_info(self, *, amount_msat: Optional[int], write_to_disk=True) -> bytes:
        payment_preimage = os.urandom(32)
        payment_hash = sha256(payment_preimage)
        info = PaymentInfo(payment_hash, amount_msat, RECEIVED, PR_UNPAID)
        await self.save_preimage(payment_hash, payment_preimage, write_to_disk=False)
        await self.save_payment_info(info, write_to_disk=False)
        if write_to_disk:
            await self.db.write()
        return payment_hash


    async def save_preimage(self, payment_hash: bytes, preimage: bytes, *, write_to_disk: bool = True):
        if sha256(preimage) != payment_hash:
            raise Exception("tried to save incorrect preimage for payment_hash")
        self.preimages[payment_hash.hex()] = preimage.hex()
        if write_to_disk:
            await self.db.write()


    async def save_payment_info(self, info: PaymentInfo, *, write_to_disk: bool = True) -> None:
        key = info.payment_hash.hex()
        assert info.status in SAVED_PR_STATUS
        with self.lock:
            self.payment_info[key] = info.amount_msat, info.direction, info.status
        if write_to_disk:
            await self.db.write()



