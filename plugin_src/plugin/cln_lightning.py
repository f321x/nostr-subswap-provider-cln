import os
from typing import NamedTuple, Optional, Callable, Awaitable, Dict, List, Tuple
from enum import IntEnum
import threading

from .cln_storage import CLNStorage
from .crypto import sha256
from .invoices import PR_UNPAID, PR_PAID, Invoice, BaseInvoice
from .cln_plugin import CLNPlugin
from .json_db import JsonDB
from .plugin_config import PluginConfig
from .utils import call_blocking_with_timeout
from .lnaddr import LnAddr


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
        self.hold_invoice_callbacks = {}
        self.lock = threading.RLock()
        self.payment_info = db.get_dict('lightning_payments')  # RHASH -> amount, direction, is_paid
        self.preimages = db.get_dict('lightning_preimages')  # RHASH -> preimage
        self._invoices = db.get_dict('invoices')  # type: Dict[str, Invoice]
        self.logger.debug("CLNLightning initialized")

    def register_hold_invoice(self, payment_hash: bytes, cb: Callable[[bytes], Awaitable[None]]):
        self.hold_invoice_callbacks[payment_hash] = cb

    def unregister_hold_invoice(self, payment_hash: bytes):
        self.hold_invoice_callbacks.pop(payment_hash)

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

    async def save_invoice(self, invoice: Invoice, *, write_to_disk: bool = True) -> None:
        key = invoice.get_id()
        if not invoice.is_lightning():
            raise NotImplementedError("save_invoice: only lightning invoices are supported")
        self._invoices[key] = invoice
        if write_to_disk:
            await self.db.write()

    def get_invoice(self, key: str) -> Optional[Invoice]:
        return self._invoices.get(key)

    async def delete_invoice(self, key: str) -> None:
        inv = self._invoices.pop(key)
        if inv is None:
            return
        await self.db.write()

    async def get_regular_bolt11_invoice(  # we generate the preimage
            self, *,
            amount_msat: Optional[int],
            message: str,
            expiry: int,  # expiration of invoice (in seconds, relative)
            fallback_address: Optional[str],
            min_final_cltv_expiry_delta: Optional[int] = None,
            preimage: Optional[bytes] = None,
    ) -> Tuple[str, str]:  # -> (bolt11, label)
        preimage_hex = None
        if preimage:
            preimage_hex = preimage.hex() if preimage else None
        label_hex = os.urandom(8).hex()
        amount_msat = "any" if amount_msat is None else amount_msat

        async with self.plugin.stdinout_mutex:
            try:
                result = self.plugin.plugin.rpc.invoice(amount_msat=amount_msat,  # any for 0 amount invoices
                                                        label=label_hex,  # unique internal identifier
                                                        description=message,
                                                        expiry=expiry,
                                                        fallbacks=fallback_address,
                                                        preimage=preimage_hex,
                                                        cltv=min_final_cltv_expiry_delta,
                                                        exposeprivatechannels=True
                                                        )
                bolt11 = result['bolt11']
            except Exception as e:
                raise Exception("get_bolt11_invoice call to CLN failed: " + str(e))
        return bolt11, label_hex

    # def get_bolt11_invoice(
    #         self, *,
    #         payment_hash: bytes,
    #         amount_msat: Optional[int],
    #         message: str,
    #         expiry: int,  # expiration of invoice (in seconds, relative)
    #         fallback_address: Optional[str],
    #         channels: Optional[Sequence[Channel]] = None,
    #         min_final_cltv_expiry_delta: Optional[int] = None,
    # ) -> Tuple[LnAddr, str]:
    #     assert isinstance(payment_hash, bytes), f"expected bytes, but got {type(payment_hash)}"
    #
    #     pair = self._bolt11_cache.get(payment_hash)
    #     if pair:
    #         lnaddr, invoice = pair
    #         assert lnaddr.get_amount_msat() == amount_msat
    #         return pair
    #
    #     assert amount_msat is None or amount_msat > 0
    #     timestamp = int(time.time())
    #     routing_hints = self.calc_routing_hints_for_invoice(amount_msat, channels=channels)
    #     self.logger.info(f"creating bolt11 invoice with routing_hints: {routing_hints}")
    #     invoice_features = self.features.for_invoice()
    #     if not self.uses_trampoline():
    #         invoice_features &= ~ LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM
    #     payment_secret = self.get_payment_secret(payment_hash)
    #     amount_btc = amount_msat/Decimal(COIN*1000) if amount_msat else None
    #     if expiry == 0:
    #         expiry = LN_EXPIRY_NEVER
    #     if min_final_cltv_expiry_delta is None:
    #         min_final_cltv_expiry_delta = MIN_FINAL_CLTV_DELTA_FOR_INVOICE
    #     lnaddr = LnAddr(
    #         paymenthash=payment_hash,
    #         amount=amount_btc,
    #         tags=[
    #             ('d', message),
    #             ('c', min_final_cltv_expiry_delta),
    #             ('x', expiry),
    #             ('9', invoice_features),
    #             ('f', fallback_address),
    #         ] + routing_hints,
    #         date=timestamp,
    #         payment_secret=payment_secret)
    #     invoice = lnencode(lnaddr, self.node_keypair.privkey)
    #     pair = lnaddr, invoice
    #     self._bolt11_cache[payment_hash] = pair
    #     return pair




