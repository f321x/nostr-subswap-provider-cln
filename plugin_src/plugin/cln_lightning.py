import asyncio
import os
import time
import traceback
from datetime import datetime
from typing import NamedTuple, Optional, Callable, Dict, Tuple, Any, List, Union
from enum import IntEnum
import threading
from decimal import Decimal

from .cln_logger import PluginLogger
from .cln_plugin import CLNPlugin
from .crypto import sha256
from .invoices import PR_UNPAID, PR_PAID, Invoice, LN_EXPIRY_NEVER
from .json_db import JsonDB
from .plugin_config import PluginConfig
from .constants import MIN_FINAL_CLTV_DELTA_FOR_CLIENT, MIN_FINAL_CLTV_DELTA_ACCEPTED, MIN_FINAL_CLTV_DELTA_FOR_INVOICE
from .utils import call_blocking_with_timeout, ShortID
from .lnutil import LnFeatures, filter_suitable_recv_chans
from .invoices import HoldInvoice, DuplicateInvoiceCreationError, Htlc, InvoiceState
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


class CLNLightning:
    INBOUND_LIQUIDITY_FACTOR = 0.9  # Buffer factor for inbound liquidity calculation (use only 90% of inbound capacity)

    def __init__(self, *, plugin_instance: CLNPlugin, config: PluginConfig, db: JsonDB, logger: PluginLogger):
        # self.MIN_FINAL_CLTV_DELTA_ACCEPTED: int = config.cln_config["cltv-final"]["value_int"]
        # self.MIN_FINAL_CLTV_DELTA_FOR_INVOICE: int = self.MIN_FINAL_CLTV_DELTA_ACCEPTED + 3

        self._rpc = plugin_instance.plugin.rpc
        plugin_instance.set_htlc_hook(self.plugin_htlc_accepted_hook)
        self._config = config
        self._db = db
        self._logger = logger
        self._hold_invoice_callbacks = {}
        self._invoice_lock = threading.RLock()
        self._payment_info_lock = threading.RLock()
        self._payment_info = db.get_dict('lightning_payments')  # RHASH -> amount, direction, is_paid
        self._preimages = db.get_dict('lightning_preimages')  # RHASH -> preimage
        self._invoices = db.get_dict('invoices')  # type: Dict[str, Invoice]
        self._hold_invoices = db.get_dict('hold_invoices')  # type: Dict[str, HoldInvoice]  # HASH[hex] -> bolt11
        self._payment_secret_key = plugin_instance.derive_secret("payment_secret")
        self.monitoring_tasks = [] # type: List[asyncio.Task]
        self._logger.debug("CLNLightning initialized")

    async def run(self):
        # put the htlc expiry monitoring in a separate thread to avoid blocking the async event loop
        htlc_expiry_watcher = asyncio.to_thread(self.monitor_expiries)
        self.monitoring_tasks.append(asyncio.create_task(htlc_expiry_watcher))

        # start the callback handler thread which checks if hold invoices are fully funded and calls the callback
        callback_handler = asyncio.to_thread(self.callback_handler)
        self.monitoring_tasks.append(asyncio.create_task(callback_handler))

        self._logger.debug("CLNLightning monitoring started")

    def monitor_expiries(self):
        """Iterate through the hold invoices and cancel expired htlcs"""
        while True:
            try:
                with self._invoice_lock:
                    for payment_hash in list(self._hold_invoices.keys()):
                        invoice = self.get_hold_invoice(bytes.fromhex(payment_hash))
                        # cancel all htlcs and delete invoice if it's expired
                        # if invoice.created_at + invoice.expiry < time.time() and invoice.funding_status is InvoiceState.UNFUNDED:
                        #     invoice.cancel_all_htlcs()  # also cancel the prepay invoice!
                        #     self._hold_invoice_callbacks.pop(invoice.payment_hash)
                        #     self._hold_invoices.pop(invoice.payment_hash)
                        #     self._db.write()
                        # cancel expired htlcs
                        if invoice.cancel_expired_htlcs():
                            self._logger.warning(f"cancel_expired_htlcs: cancelled expired htlcs for invoice {invoice.payment_hash}")
                            self.update_invoice(invoice)
            except Exception as e:
                self._logger.error(f"monitor_expiries loop encountered an error:\n{traceback.format_exc()}")
            time.sleep(10)

    def callback_handler(self):
        """Iterate through the hold invoices and call the callback if the invoice is fully funded"""
        while True:
            try:
                for payment_hash, callback in list(self._hold_invoice_callbacks.items()):
                    with self._invoice_lock:
                        invoice = self.get_hold_invoice(payment_hash)
                        if invoice is None:
                            # no hold invoice has been saved before registering this callback
                            self._logger.error(f"callback_handler: hold invoice {payment_hash} not found")
                            self._hold_invoice_callbacks.pop(payment_hash)
                            continue
                        if invoice.funding_status is InvoiceState.FUNDED:
                            prepay_invoice_hash = invoice.get_prepay_invoice()
                            if prepay_invoice_hash is not None:  # check if there is a prepay invoice attached
                                prepay_invoice = self.get_hold_invoice(prepay_invoice_hash)
                                if prepay_invoice.funding_status is InvoiceState.FUNDED:
                                    # redeem the prepay invoice first
                                    prepay_invoice.settle(self.get_preimage(prepay_invoice_hash))
                                    self.update_invoice(prepay_invoice)
                                    self._logger.debug(f"callback_handler: prepay invoice "
                                                        f"{prepay_invoice.payment_hash.hex()} redeemed")
                                else:  # prepay invoice not yet funded, so we wait for it to be funded
                                    continue
                            self._logger.debug(f"callback_handler: invoice {invoice.payment_hash.hex()} fully funded, "
                                                f"calling callback")

                            # Call the callback
                            callback(invoice.payment_hash)
                            self.unregister_hold_invoice_callback(invoice.payment_hash)

            except Exception as e:
                self._logger.error(f"callback_handler encountered an error:\n{traceback.format_exc()}")
            time.sleep(5)

    def plugin_htlc_accepted_hook(self, onion, htlc, request, plugin, *args, **kwargs) -> None:
        if "forward_to" in kwargs:  # ignore forwards
            self._logger.debug(f"plugin_htlc_accepted_hook: ignoring forward htlc")
            return request.set_result({"result": "continue"})

        with self._invoice_lock:
            invoice = self.get_hold_invoice(bytes.fromhex(htlc["payment_hash"]))
            if invoice is None:  # htlc doesn't belong to a hold invoice we know about
                self._logger.debug(f"plugin_htlc_accepted_hook: htlc for unknown invoice")
                return request.set_result({"result": "continue"})

            # htlc that affects one of our stored hold invoices
            try:
                if self.handle_htlc(invoice, htlc, onion, request):
                    self.update_invoice(invoice)  # saves the changes to the invoice
            except Exception as e:
                self._logger.error(f"plugin_htlc_accepted_hook failed:\n{traceback.format_exc()}")
                return request.set_result({"result": "continue"})

    def update_invoice(self, invoice: HoldInvoice) -> None:
        """Update the invoice in the db so it reflects all internal changes by calling __setattr__ in the StoredDict"""
        self._hold_invoices.pop(invoice.payment_hash.hex())
        self._hold_invoices[invoice.payment_hash.hex()] = invoice
        self._db.write()

    def handle_htlc(self, target_invoice: HoldInvoice, incoming_htlc: dict[str, Any], onion, request) -> bool:
        """Validates and stores the incoming htlc, returns True if changes need to be saved in db
        CLN will replay all unresolved HTLCs on restart"""
        self._logger.debug(f"handle_htlc: {incoming_htlc}")
        htlc = Htlc.from_cln_dict(incoming_htlc, request)
        if (existing := target_invoice.find_htlc(htlc)) is not None:
            existing.add_new_htlc_callback(request)
            self._logger.debug(f"handle_htlc: registering new callback for existing htlc invoice: {target_invoice.payment_hash.hex()}")
            return False # we already received this htlc and don't have to store it again (e.g. after replay when restarting)
        else:
            # add the htlc to the invoice
            target_invoice.incoming_htlcs.add(htlc)

        try:
            # decode target invoice using cln rpc
            decoded_invoice = self._rpc.decodepay(target_invoice.bolt11)
        except Exception as e:
            self._logger.error(f"handle_htlc: decodepay rpc failed: {e}")
            htlc.fail()
            return True

        if target_invoice.funding_status is InvoiceState.FAILED:
            # invoice is already failed, we don't accept any further htlcs for it
            self._logger.warning(f"handle_htlc: invoice {target_invoice.payment_hash} is already failed")
            htlc.fail()
            return True

        if (incoming_htlc["cltv_expiry_relative"] < decoded_invoice["min_final_cltv_expiry"] or
            incoming_htlc["cltv_expiry_relative"] < MIN_FINAL_CLTV_DELTA_ACCEPTED):
            self._logger.warning(f"handle_htlc: Too short cltv: ({incoming_htlc['cltv_expiry_relative']} < "
                               f"{decoded_invoice['min_final_cltv_expiry']})")
            htlc.fail()
            return True

        # check if the payment secret is correct (and existing)
        if "payment_secret" not in onion or onion["payment_secret"] != decoded_invoice["payment_secret"]:
            self._logger.warning(f"handle_htlc: htlc with none or incorrect payment secret for "
                                  f"invoice {target_invoice.payment_hash}")
            htlc.fail()
            return True

        if target_invoice.funding_status != InvoiceState.UNFUNDED:
            self._logger.warning(f"handle_htlc: invoice {target_invoice.payment_hash} is already paid, "
                                  f"no new htlcs accepted")
            htlc.fail()
            return True

        # check if we now have enough htlcs to satisfy the invoice, redeem them if so
        if target_invoice.is_fully_funded():
            target_invoice.funding_status = InvoiceState.FUNDED

        self._logger.debug(f"handle_htlc: htlc accepted for invoice {target_invoice.payment_hash.hex()}, "
                           f"value: {htlc.amount_msat}")
        return True

    async def pay_invoice(self, *, bolt11: str, attempts: int) -> (bool, str):  # -> (success, log)
        try:  # first check if payment was already initiated earlier
            existing_pay_req = self._rpc.listpays(bolt11=bolt11)
            if existing_pay_req['status'] == 'complete':
                return True, existing_pay_req['preimage']
            elif existing_pay_req['status'] == "pending":
                return False, f"payment is already pending {existing_pay_req['status']}"
        except Exception as e:
            pass

        retry_for = attempts * 45 if attempts > 1 else 60  # CLN automatically retries for the given amount of time
        try:
            result = await call_blocking_with_timeout(self._rpc.pay(bolt11=bolt11, retry_for=retry_for),
                                                timeout=retry_for + 30)
        except Exception as e:
            return False, "pay_invoice call to CLN failed: " + str(e)

        if 'payment_preimage' in result and result['payment_preimage'] and result['status'] == 'complete':
            return True, result['payment_preimage']
        return False, result

    def create_payment_info(self, *, amount_msat: Optional[int], write_to_disk=True) -> bytes:
        payment_preimage = os.urandom(32)
        payment_hash = sha256(payment_preimage)
        info = PaymentInfo(payment_hash, amount_msat, RECEIVED, PR_UNPAID)
        self.save_preimage(payment_hash, payment_preimage, write_to_disk=False)
        self._save_payment_info(info, write_to_disk=False)
        if write_to_disk:
            self._db.write()
        return payment_hash

    def save_preimage(self, payment_hash: bytes, preimage: bytes, *, write_to_disk: bool = True):
        if sha256(preimage) != payment_hash:
            raise InvalidPreimageSavedError("tried to save incorrect preimage for payment_hash")
        self._preimages[payment_hash.hex()] = preimage.hex()
        if write_to_disk:
            self._db.write()

    def _save_payment_info(self, info: PaymentInfo, *, write_to_disk: bool = True) -> None:
        key = info.payment_hash.hex()
        assert info.status in SAVED_PR_STATUS
        with self._payment_info_lock:
            self._payment_info[key] = info.amount_msat, info.direction, info.status
        if write_to_disk:
            self._db.write()

    def delete_payment_info(self, payment_hash: Union[bytes, str]) -> None:
        """Used to delete remaining payment info after a swap has been completed or failed"""
        if isinstance(payment_hash, bytes):
            payment_hash = payment_hash.hex()
        with self._payment_info_lock:
            info_res = self._payment_info.pop(payment_hash, None)
            preimage_res = self._preimages.pop(payment_hash, None)
        if info_res is None and preimage_res is None:
            return
        self._db.write()

    def save_invoice(self, invoice: Invoice, *, write_to_disk: bool = True) -> None:
        key = invoice.get_id()
        if not invoice.is_lightning():
            raise NotImplementedError("save_invoice: only lightning invoices are supported")
        self._invoices[key] = invoice
        if write_to_disk:
            self._db.write()

    def get_invoice(self, key: str) -> Optional[Invoice]:
        return self._invoices.get(key)

    def get_hold_invoice(self, payment_hash: Union[str, bytes]) -> Optional[HoldInvoice]:
        if isinstance(payment_hash, bytes):
            payment_hash = payment_hash.hex()
        return self._hold_invoices.get(payment_hash)

    def delete_invoice(self, key: str) -> None:
        inv = self._invoices.pop(key, None)
        if inv is None:
            return
        self._db.write()

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
            result = self._rpc.invoice(amount_msat=amount_msat,  # any for 0 amount invoices
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

    def register_hold_invoice_callback(self, payment_hash: Union[bytes, str], callback: Callable) -> None:
        """Used to register the swap invoice (not prepay invoice) with the callback manager"""
        if isinstance(payment_hash, bytes):
            payment_hash = payment_hash.hex()
        self._hold_invoice_callbacks[payment_hash] = callback

    def unregister_hold_invoice_callback(self, payment_hash: Union[bytes, str]) -> None:
        """Used to unregister the swap invoice from the callback manager"""
        if isinstance(payment_hash, bytes):
            payment_hash = payment_hash.hex()
        self._hold_invoice_callbacks.pop(payment_hash)

    def save_hold_invoice(self, invoice: HoldInvoice) -> None:
        """Saves a hold invoice to the db"""
        self._hold_invoices[invoice.payment_hash.hex()] = invoice
        self._db.write()

    def delete_hold_invoice(self, payment_hash: bytes) -> None:
        res = self._hold_invoices.pop(payment_hash.hex(), None)
        if res is None:
            return
        self._db.write()

    def b11invoice_from_hash(self, *,
            payment_hash: bytes,
            amount_msat: int,
            message: Optional[str] = "",
            expiry: int,  # expiration of invoice (in seconds, relative)
            fallback_address: Optional[str] = None,
            min_final_cltv_expiry_delta: Optional[int] = None,
            store_invoice: bool = True) -> HoldInvoice:
        assert amount_msat > 0, f"b11invoice_from_hash: amount_msat must be > 0, but got {amount_msat}"
        if len(payment_hash) != 32:
            raise InvalidInvoiceCreationError("b11invoice_from_hash: payment_hash "
                                              "must be 32 bytes, was " + str(len(payment_hash)))
        if len(self._rpc.listinvoices(payment_hash=payment_hash.hex())["invoices"]) > 0:
            raise DuplicateInvoiceCreationError("b11invoice_from_hash: "
                                                "invoice already exists in cln: " + payment_hash.hex())

        invoice_features = LnFeatures(0) | LnFeatures.VAR_ONION_REQ | LnFeatures.PAYMENT_SECRET_REQ | LnFeatures.BASIC_MPP_OPT
        routing_hints = self._get_route_hints(amount_msat)
        lnaddr = LnAddr(
            net=self._config.network,
            paymenthash=payment_hash,
            amount=Decimal(amount_msat) / Decimal(COIN*1000),
            tags=[
                     ('c', MIN_FINAL_CLTV_DELTA_FOR_INVOICE if min_final_cltv_expiry_delta is None
                                                                else min_final_cltv_expiry_delta),
                     ('d', message if message and len(message) > 0 else f"swap {datetime.now()}"),
                     ('x', LN_EXPIRY_NEVER if expiry == 0 else expiry),
                     ('9', invoice_features),
                     ('f', fallback_address),
                 ] + routing_hints,
            date=int(time.time()),
            payment_secret=self._get_payment_secret(payment_hash))
        b11invoice_unsigned: str = lnencode_unsigned(lnaddr)
        try:
             self._logger.debug(f"b11invoice_from_hash: unsigned invoice: {b11invoice_unsigned}")
             signed = self._rpc.call(
                 "signinvoice",
                 {
                     "invstring": b11invoice_unsigned,
                 },
             )["bolt11"]
             self._logger.debug(f"b11invoice_from_hash: signed invoice: {signed}")
        except Exception as e:
            self._logger.error(f"b11invoice_from_hash: signinvoice rpc failed: {e}")
            raise Bolt11InvoiceCreationError("signinvoice rpc failed: " + str(e))
        invoice = HoldInvoice(payment_hash, signed, amount_msat, expiry)
        if store_invoice:
            self.save_hold_invoice(invoice)
        return invoice

    def _get_route_hints(self, amount_msat: int) -> List[Tuple[str, List[Tuple[bytes, ShortID, int, int, int]]]]:
        if amount_msat is None or amount_msat == 0:
            raise NotImplementedError  # swaps always have the amount defined
        try:
            available_channels = self._rpc.listpeerchannels()["channels"]
        except Exception as e:
            self._logger.error(f"_get_route_hints rpc failed: {e}")
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

    def _get_payment_secret(self, payment_hash: Union[str, bytes]) -> bytes:
        if isinstance(payment_hash, str):
            payment_hash = bytes.fromhex(payment_hash)
        assert len(payment_hash) == 32, f"_get_payment_secret: payment_hash must be 32 bytes, was {len(payment_hash)}"
        return sha256(sha256(self._payment_secret_key) + payment_hash)

    def bundle_payments(self, *, swap_invoice: HoldInvoice, prepay_invoice: HoldInvoice) -> None:
        current_invoice = self.get_hold_invoice(swap_invoice.payment_hash)
        # remove the old invoice so changes are tracked by the JsonDB StoredDict
        self._hold_invoices.pop(swap_invoice.payment_hash.hex())
        current_invoice.attach_prepay_invoice(prepay_invoice.payment_hash)
        # then store the updated invoice with the prepay invoice attached
        self.save_hold_invoice(current_invoice)

    def get_preimage(self, payment_hash: Union[bytes, str]) -> Optional[bytes]:
        if isinstance(payment_hash, str):
            payment_hash = bytes.fromhex(payment_hash)
        assert len(payment_hash) == 32, f"get_preimage: payment_hash must be 32 bytes, was {len(payment_hash)}"
        preimage_hex = self._preimages.get(payment_hash.hex())
        if preimage_hex is None:
            return None
        preimage_bytes = bytes.fromhex(preimage_hex)
        if sha256(preimage_bytes) != payment_hash:
            raise InvalidPreimageFoundError("found incorrect preimage for payment_hash")
        return preimage_bytes

    def num_sats_can_receive(self) -> int:
        """returns max inbound capacity"""
        inbound_capacity_sat = 0
        try:
            available_channels = self._rpc.listfunds()["channels"]
        except Exception as e:
            self._logger.error(f"num_sats_can_receive: listfunds rpc failed: {e}")
            return 0
        for channel in available_channels:
            if channel["connected"]:
                inbound_capacity_sat += (channel["amount_msat"] - channel["our_amount_msat"]) / 1000
        return int(inbound_capacity_sat * self.INBOUND_LIQUIDITY_FACTOR)

    def num_sats_can_send(self) -> int:
        """returns max outbound capacity"""
        outbound_capacity_sat = 0
        try:
            available_channels = self._rpc.listfunds()["channels"]
        except Exception as e:
            self._logger.error(f"num_sats_can_send: listfunds rpc failed: {e}")
            return 0
        for channel in available_channels:
            if channel["connected"]:
                outbound_capacity_sat += channel["our_amount_msat"] / 1000
        return int(outbound_capacity_sat * self.INBOUND_LIQUIDITY_FACTOR)


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
