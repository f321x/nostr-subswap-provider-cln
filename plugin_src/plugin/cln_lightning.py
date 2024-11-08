import asyncio
import os
import sys
import time
from typing import NamedTuple, Optional, Callable, Dict, Tuple, Any, List
from enum import IntEnum
import threading
from decimal import Decimal

from .cln_logger import PluginLogger
from .cln_plugin import CLNPlugin
from .crypto import sha256
from .invoices import PR_UNPAID, PR_PAID, Invoice, BaseInvoice, LN_EXPIRY_NEVER
from .json_db import JsonDB
from .plugin_config import PluginConfig
from .submarine_swaps import MIN_FINAL_CLTV_DELTA_FOR_CLIENT
from .utils import call_blocking_with_timeout, ShortID
from .lnutil import (LnFeatures, filter_suitable_recv_chans, HoldInvoice, DuplicateInvoiceCreationError, Htlc,
                     HtlcState, InvoiceState)
from .lnaddr import LnAddr, lnencode_unsigned
from .bitcoin import COIN


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

# def ensure_db_write(func):
#     def wrapper(self, *args, **kwargs):
#         try:
#             return func(self, *args, **kwargs)
#         finally:
#             self.__db.write()
#     return wrapper

class CLNLightning:
    def __init__(self, *, plugin_instance: CLNPlugin, config: PluginConfig, db: JsonDB, logger: PluginLogger):
        self.__rpc = plugin_instance.plugin.rpc
        plugin_instance.set_htlc_hook(self.plugin_htlc_accepted_hook)
        self.__config = config
        self.__db = db
        self.__logger = logger
        self.__hold_invoice_callbacks = {}
        self.__invoice_lock = threading.RLock()
        self.__payment_info_lock = threading.RLock()
        self.__payment_info = db.get_dict('lightning_payments')  # RHASH -> amount, direction, is_paid
        self.__preimages = db.get_dict('lightning_preimages')  # RHASH -> preimage
        self.__invoices = db.get_dict('invoices')  # type: Dict[str, Invoice]
        # todo: make HoldInvoice StoredObject
        self.__hold_invoices = db.get_dict('hold_invoices')  # type: Dict[bytes, HoldInvoice]  # HASH -> bolt11
        self.__logger.debug("CLNLightning initialized")
        self.__payment_secret_key = plugin_instance.derive_secret("payment_secret")
        self.monitoring_tasks = [] # type: List[asyncio.Task]

    async def run(self):
        # put the htlc expiry monitoring in a separate thread to avoid blocking the async event loop
        htlc_expiry_watcher = asyncio.to_thread(self.monitor_expiries)
        self.monitoring_tasks.append(await asyncio.create_task(htlc_expiry_watcher))

        # start the callback handler thread which checks if hold invoices are fully funded and calls the callback
        callback_handler = asyncio.to_thread(self.callback_handler)
        self.monitoring_tasks.append(await asyncio.create_task(callback_handler))

        self.__logger.debug("CLNLightning monitoring started")

    def monitor_expiries(self):
        """Iterate through the hold invoices and cancel expired htlcs"""
        while True:
            try:
                with self.__invoice_lock:
                    for payment_hash in list(self.__hold_invoices.keys()):
                        invoice = self.get_hold_invoice(payment_hash)
                        # cancel all htlcs and delete invoice if it's expired
                        # if invoice.created_at + invoice.expiry < time.time() and invoice.funding_status is InvoiceState.UNFUNDED:
                        #     invoice.cancel_all_htlcs()  # also cancel the prepay invoice!
                        #     self.__hold_invoice_callbacks.pop(invoice.payment_hash)
                        #     self.__hold_invoices.pop(invoice.payment_hash)
                        #     self.__db.write()
                        # cancel expired htlcs
                        if invoice.cancel_expired_htlcs():
                            self.__logger.warning(f"cancel_expired_htlcs: cancelled expired htlcs for invoice {invoice.payment_hash}")
                            self.__db.write()
            except Exception as e:
                self.__logger.error(f"monitor_expiries loop encountered an error: {e}")
            time.sleep(10)

    def callback_handler(self):
        """Iterate through the hold invoices and call the callback if the invoice is fully funded"""
        while True:
            try:
                for payment_hash, callback in list(self.__hold_invoice_callbacks.items()):
                    with self.__invoice_lock:
                        invoice = self.get_hold_invoice(payment_hash)
                        if invoice is None:
                            # no hold invoice has been saved before registering this callback
                            self.__logger.error(f"callback_handler: hold invoice {payment_hash} not found")
                            self.__hold_invoice_callbacks.pop(payment_hash)
                            continue
                        if invoice.funding_status is InvoiceState.FUNDED:
                            prepay_invoice = invoice.get_prepay_invoice()
                            if prepay_invoice is not None:
                                if prepay_invoice.funding_status is InvoiceState.FUNDED:
                                    # redeem the prepay invoice first
                                    prepay_invoice.settle(self.get_preimage(prepay_invoice.payment_hash))
                                    self.__db.write()
                                else:
                                    self.__logger.warning(f"callback_handler: prepay invoice "
                                                          f"{prepay_invoice.payment_hash} not funded, but swap invoice is")
                                    continue
                            self.__logger.debug(f"callback_handler: invoice {invoice.payment_hash} fully funded, "
                                                f"calling callback")
                            # Call the callback outside the lock
                            self.__invoice_lock.release()
                            try:
                                callback(invoice.payment_hash)
                                self.unregister_hold_invoice(invoice.payment_hash)
                            finally:
                                self.__invoice_lock.acquire()
            except Exception as e:
                self.__logger.error(f"callback_handler encountered an error: {e}")
            time.sleep(9)

    def plugin_htlc_accepted_hook(self, onion, htlc, request, plugin, *args, **kwargs) -> None:
        self.__logger.debug("htlc_accepted hook called")
        if "forward_to" in kwargs:  # ignore forwards
            return request.set_result({"result": "continue"})

        with self.__invoice_lock:
            invoice = self.get_hold_invoice(bytes.fromhex(htlc["payment_hash"]))
            if invoice is None or invoice.funding_status:  # not a hold invoice we know about
                return request.set_result({"result": "continue"})

            # htlc that affects one of our stored hold invoices
            try:
                if self.handle_htlc(invoice, htlc, onion, request):
                    self.__db.write()  # saves the changes to the invoice
            except Exception as e:
                self.__logger.error(f"plugin_htlc_accepted_hook failed: {e}")
                return request.set_result({"result": "continue"})

    def handle_htlc(self, target_invoice: HoldInvoice, incoming_htlc: dict[str, Any], onion, request) -> bool:
        """Validates and stores the incoming htlc, returns True if changes need to be saved in db"""
        htlc = Htlc.from_dict(incoming_htlc, request)
        if (existing := target_invoice.find_htlc(htlc.short_channel_id, htlc.channel_id)) is not None:
            return False # we already received this htlc and don't have to store it again (e.g. after replay when restarting)
            # return self.__handle_existing_invoice(target_invoice, existing, request)
        else:
            # add the htlc to the invoice
            target_invoice.incoming_htlcs.add(htlc)

        try:
            # decode target invoice using cln rpc
            decoded_invoice = self.__rpc.decodepay(target_invoice.bolt11)
        except Exception as e:
            self.__logger.error(f"handle_htlc: decodepay rpc failed: {e}")
            htlc.fail()
            return True

        if target_invoice.funding_status is InvoiceState.FAILED:
            # invoice is already failed, we don't accept any further htlcs for it
            self.__logger.warning(f"handle_htlc: invoice {target_invoice.payment_hash} is already failed")
            htlc.fail()
            return True

        if incoming_htlc["cltv_expiry_relative"] < decoded_invoice["min_final_cltv_expiry"]:
            self.__logger.warning(f"handle_htlc: Too short cltv: ({incoming_htlc['cltv_expiry_relative']} < "
                               f"{decoded_invoice['min_final_cltv_expiry']})")
            htlc.fail()
            return True

        # check if the payment secret is correct (and existing)
        if "payment_secret" not in onion or onion["payment_secret"] != decoded_invoice["payment_secret"]:
            self.__logger.warning(f"handle_htlc: htlc with none or incorrect payment secret for "
                                  f"invoice {target_invoice.payment_hash}")
            htlc.fail()
            return True

        if target_invoice.funding_status != InvoiceState.UNFUNDED:
            self.__logger.warning(f"handle_htlc: invoice {target_invoice.payment_hash} is already paid, "
                                  f"no new htlcs accepted")
            htlc.fail()
            return True

        # check if we now have enough htlcs to satisfy the invoice, redeem them if so
        if target_invoice.is_fully_funded():
            target_invoice.funding_status = InvoiceState.FUNDED

        return True


    # def __handle_existing_invoice(self, target_invoice: HoldInvoice, htlc: Htlc, request):
    #     match htlc.state:
    #         case HtlcState.Accepted:
    #            pass
    #         case HtlcState.Settled:
    #             pass
    #         case HtlcState.Cancelled:
    #             pass

    # async def pay_invoice(self, *, bolt11: str, attempts: int) -> (bool, str):  # -> (success, log)
    #     retry_for = attempts * 45 if attempts > 1 else 60  # CLN automatically retries for the given amount of time
    #     try:
    #         result = await call_blocking_with_timeout(self.rpc.pay(bolt11=bolt11, retry_for=retry_for),
    #                                             timeout=retry_for + 30)
    #     except Exception as e:
    #         return False, "pay_invoice call to CLN failed: " + str(e)
    #
    #     # check if the payment was successful, currently we assume it failed if it's not "complete"
    #     if 'payment_preimage' in result and result['payment_preimage'] and result['status'] == 'complete':
    #     :TODO is complete suitable?
    #         return True, result['payment_preimage']
    #     return False, result

    def create_payment_info(self, *, amount_msat: Optional[int], write_to_disk=True) -> bytes:
        payment_preimage = os.urandom(32)
        payment_hash = sha256(payment_preimage)
        info = PaymentInfo(payment_hash, amount_msat, RECEIVED, PR_UNPAID)
        self.__save_preimage(payment_hash, payment_preimage, write_to_disk=False)
        self.__save_payment_info(info, write_to_disk=False)
        if write_to_disk:
            self.__db.write()
        return payment_hash

    def __save_preimage(self, payment_hash: bytes, preimage: bytes, *, write_to_disk: bool = True):
        if sha256(preimage) != payment_hash:
            raise InvalidPreimageSavedError("tried to save incorrect preimage for payment_hash")
        self.__preimages[payment_hash.hex()] = preimage.hex()
        if write_to_disk:
            self.__db.write()

    def __save_payment_info(self, info: PaymentInfo, *, write_to_disk: bool = True) -> None:
        key = info.payment_hash.hex()
        assert info.status in SAVED_PR_STATUS
        with self.__payment_info_lock:
            self.__payment_info[key] = info.amount_msat, info.direction, info.status
        if write_to_disk:
            self.__db.write()

    # def save_invoice(self, invoice: Invoice, *, write_to_disk: bool = True) -> None:
    #     key = invoice.get_id()
    #     if not invoice.is_lightning():
    #         raise NotImplementedError("save_invoice: only lightning invoices are supported")
    #     self.__invoices[key] = invoice
    #     if write_to_disk:
    #         self.__db.write()

    # def get_invoice(self, key: str) -> Optional[Invoice]:
    #     return self.__invoices.get(key)

    def get_hold_invoice(self, payment_hash: bytes) -> Optional[HoldInvoice]:
        return self.__hold_invoices.get(payment_hash)

    # def delete_invoice(self, key: str) -> None:
    #     inv = self.__invoices.pop(key)
    #     if inv is None:
    #         return
    #     self.__db.write()

    def get_regular_bolt11_invoice(  # we generate the preimage
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
        label_hex = os.urandom(8).hex()  # unique internal identifier, can be used to fetch invoice status later
        amount_msat = "any" if amount_msat is None else amount_msat

        try:
            result = self.__rpc.invoice(amount_msat=amount_msat,  # any for 0 amount invoices
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
            raise ClnRpcError("get_bolt11_invoice call to CLN failed: " + str(e))
        return bolt11, label_hex

    def register_hold_invoice(self, payment_hash: bytes, callback: Callable):
        self.__hold_invoice_callbacks[payment_hash] = callback

    def unregister_hold_invoice(self, payment_hash: bytes):
        self.__hold_invoice_callbacks.pop(payment_hash)

    def save_hold_invoice(self, invoice: HoldInvoice):
        self.__hold_invoices[invoice.payment_hash] = invoice
        self.__db.write()

    def __delete_hold_invoice(self, payment_hash: bytes):
        self.__hold_invoices.pop(payment_hash)
        self.__db.write()

    def save_forwarding_failure(self, payment_key_hex: str, failure_msg: str):
        pass

    def b11invoice_from_hash(self, *,
            payment_hash: bytes,
            amount_msat: int,
            message: str,
            expiry: int,  # expiration of invoice (in seconds, relative)
            fallback_address: Optional[str],
            min_final_cltv_expiry_delta: Optional[int] = None) -> HoldInvoice:
        assert amount_msat > 0, f"b11invoice_from_hash: amount_msat must be > 0, but got {amount_msat}"
        if len(payment_hash) != 64:
            raise InvalidInvoiceCreationError("b11invoice_from_hash: payment_hash "
                                              "must be 32 bytes, was " + str(len(payment_hash)))
        if len(self.__rpc.listinvoices(payment_hash=payment_hash.hex())["invoices"]) > 0:
            raise DuplicateInvoiceCreationError("b11invoice_from_hash: "
                                                "invoice already exists in cln: " + payment_hash.hex())

        invoice_features = LnFeatures.VAR_ONION_REQ | LnFeatures.PAYMENT_SECRET_REQ | LnFeatures.BASIC_MPP_OPT
        routing_hints = self.__get_route_hints(amount_msat)
        lnaddr = LnAddr(
            paymenthash=payment_hash,
            amount=amount_msat/Decimal(COIN*1000),
            tags=[
                     ('d', message),
                     ('c', MIN_FINAL_CLTV_DELTA_FOR_CLIENT if min_final_cltv_expiry_delta is None
                                                                else min_final_cltv_expiry_delta),
                     ('x', LN_EXPIRY_NEVER if expiry == 0 else expiry),
                     ('9', invoice_features),
                     ('f', fallback_address),
                 ] + routing_hints,
            date=int(time.time()),
            payment_secret=self.__get_payment_secret(payment_hash))
        b11invoice_unsigned: str = lnencode_unsigned(lnaddr)
        try:
             signed = self.__rpc.call(
                 "signinvoice",
                 {
                     "invstring": b11invoice_unsigned,
                 },
             )["bolt11"]
        except Exception as e:
            self.__logger.error(f"b11invoice_from_hash: signinvoice rpc failed: {e}")
            raise Bolt11InvoiceCreationError("signinvoice rpc failed: " + str(e))
        invoice = HoldInvoice(payment_hash, signed, amount_msat, expiry)
        return invoice

    def __get_route_hints(self, amount_msat: int):
        if amount_msat is None or amount_msat is 0:
            raise NotImplementedError  # swaps always have the amount defined
        try:
            available_channels = self.__rpc.listpeerchannels()["channels"]
        except Exception as e:
            self.__logger.error(f"__get_route_hints rpc failed: {e}")
            return []

        suitable_channels = filter_suitable_recv_chans(amount_msat,
                                                            available_channels)
        routing_hints = []
        for channel in suitable_channels:
            short_id = ShortID.from_str(channel["short_channel_id"])
            routing_hints.append(('r', [(
                bytes.fromhex(channel["peer_id"]),
                short_id,
                int(channel["updates"]["remote"]["fee_base_msat"]),
                int(channel["updates"]["remote"]["fee_proportional_millionths"]),
                int(channel["updates"]["remote"]["cltv_expiry_delta"]))]))

        return routing_hints

    def __get_payment_secret(self, payment_hash: bytes) -> bytes:
        return sha256(sha256(self.__payment_secret_key) + payment_hash)

    # def add_payment_info_for_hold_invoice(self, payment_hash: bytes, amount_msat: int):
    #     pass

    def bundle_payments(self, *, swap_invoice: HoldInvoice, prepay_invoice: HoldInvoice):
        self.__hold_invoices[swap_invoice.payment_hash].attach_prepay_invoice(prepay_invoice)
        self.__db.write()

    def get_preimage(self, payment_hash: bytes) -> Optional[bytes]:
        assert isinstance(payment_hash, bytes), f"expected bytes, but got {type(payment_hash)}"
        preimage_hex = self.__preimages.get(payment_hash.hex())
        if preimage_hex is None:
            return None
        preimage_bytes = bytes.fromhex(preimage_hex)
        if sha256(preimage_bytes) != payment_hash:
            raise InvalidPreimageFoundError("found incorrect preimage for payment_hash")
        return preimage_bytes

    def num_sats_can_receive(self) -> int:
        """returns max inbound capacity"""
        pass




class InvalidInvoiceCreationError(Exception):
    pass

class InvalidPreimageFoundError(Exception):
    pass

class ClnRpcError(Exception):
    pass

class InvalidPreimageSavedError(Exception):
    pass

class Bolt11InvoiceCreationError(Exception):
    pass

class InvoiceNotFoundError(Exception):
    pass
