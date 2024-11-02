import os
import sys
import time
from typing import NamedTuple, Optional, Callable, Awaitable, Dict, List, Tuple, Sequence
from enum import IntEnum
import threading

from .cln_logger import PluginLogger
from .cln_plugin import CLNPlugin
from .crypto import sha256
from .invoices import PR_UNPAID, PR_PAID, Invoice, BaseInvoice
from .json_db import JsonDB
from .plugin_config import PluginConfig
from .utils import call_blocking_with_timeout, ShortID
from .lnutil import LnFeatures
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
    def __init__(self, *, plugin_instance: CLNPlugin, config: PluginConfig, db: JsonDB, logger: PluginLogger):
        self.__rpc = plugin_instance.plugin.rpc
        plugin_instance.set_htlc_hook(self.plugin_htlc_accepted_hook)
        self.__config = config
        self.__db = db
        self.__logger = logger
        self.__hold_invoice_callbacks = {}
        self.__lock = threading.RLock()
        self.__payment_info = db.get_dict('lightning_payments')  # RHASH -> amount, direction, is_paid
        self.__preimages = db.get_dict('lightning_preimages')  # RHASH -> preimage
        self.__invoices = db.get_dict('invoices')  # type: Dict[str, Invoice]
        self.__logger.debug("CLNLightning initialized")
        self.__payment_secret_key = plugin_instance.derive_secret("payment_secret")

    def plugin_htlc_accepted_hook(self, onion, htlc, request, plugin, *args, **kwargs):
        print("htlc_accepted hook called print", file=sys.stderr)
        self.__logger.debug("htlc_accepted hook called")
        return {"result": "continue"}

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
        self.save_preimage(payment_hash, payment_preimage, write_to_disk=False)
        self.save_payment_info(info, write_to_disk=False)
        if write_to_disk:
            self.__db.write()
        return payment_hash

    def save_preimage(self, payment_hash: bytes, preimage: bytes, *, write_to_disk: bool = True):
        if sha256(preimage) != payment_hash:
            raise InvalidPreimageSavedError("tried to save incorrect preimage for payment_hash")
        self.__preimages[payment_hash.hex()] = preimage.hex()
        if write_to_disk:
            self.__db.write()

    def save_payment_info(self, info: PaymentInfo, *, write_to_disk: bool = True) -> None:
        key = info.payment_hash.hex()
        assert info.status in SAVED_PR_STATUS
        with self.__lock:
            self.__payment_info[key] = info.amount_msat, info.direction, info.status
        if write_to_disk:
            self.__db.write()

    def save_invoice(self, invoice: Invoice, *, write_to_disk: bool = True) -> None:
        key = invoice.get_id()
        if not invoice.is_lightning():
            raise NotImplementedError("save_invoice: only lightning invoices are supported")
        self.__invoices[key] = invoice
        if write_to_disk:
            self.__db.write()

    def get_invoice(self, key: str) -> Optional[Invoice]:
        return self.__invoices.get(key)

    def delete_invoice(self, key: str) -> None:
        inv = self.__invoices.pop(key)
        if inv is None:
            return
        self.__db.write()

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

    def save_forwarding_failure(self, payment_key_hex: str, failure_msg: str):
        pass

    def b11invoice_from_hash(self, *,
            payment_hash: bytes,
            amount_msat: int,
            message: str,
            expiry: int,  # expiration of invoice (in seconds, relative)
            fallback_address: Optional[str],
            min_final_cltv_expiry_delta: Optional[int] = None) -> str:
        assert amount_msat > 0, f"b11invoice_from_hash: amount_msat must be > 0, but got {amount_msat}"
        if len(payment_hash) != 64:
            raise InvalidInvoiceCreationError("b11invoice_from_hash: payment_hash "
                                              "must be 32 bytes, was " + str(len(payment_hash)))
        if len(self.__rpc.listinvoices(payment_hash=payment_hash.hex())["invoices"]) > 0:
            raise DuplicateInvoiceCreationError("b11invoice_from_hash: "
                                                "invoice already exists in cln: " + payment_hash.hex())

        invoice_features = LnFeatures(0)
        invoice_features |= LnFeatures.VAR_ONION_REQ
        invoice_features |= LnFeatures.PAYMENT_SECRET_REQ
        invoice_features |= LnFeatures.BASIC_MPP_OPT
        # invoice_features &= LnFeatures.
        routing_hints = self.__get_route_hints(amount_msat)
        lnaddr = LnAddr(
            paymenthash=payment_hash,
            amount=(amount_msat/1000)/COIN,
            tags=[
                     ('d', message),
                     ('c', min_final_cltv_expiry_delta),
                     ('x', expiry),
                     ('9', invoice_features),
                     ('f', fallback_address),
                 ] + routing_hints,
            date=int(time.time()),
            payment_secret=self.__get_payment_secret(payment_hash))
        b11invoice_unsigned: str = lnencode_unsigned(lnaddr)
        # try
        signed = self.__rpc.call(
            "signinvoice",
            {
                "invstring": b11invoice_unsigned,
            },
        )["bolt11"]

        try:
            hi = HoldInvoice(
                state=InvoiceState.Unpaid,
                bolt11=signed,
                amount_msat=amount_msat,
                payment_hash=payment_hash,
                payment_preimage=None,
                htlcs=Htlcs(),
                created_at=time_now(),
            )
            self.ds.save_invoice(hi)
            self.tracker.send_update(hi.payment_hash, hi.bolt11, hi.state)
            self._plugin.log(f"Added hold invoice {payment_hash} for {amount_msat}")
        except RpcError as e:
            # noinspection PyTypeChecker
            if e.error["code"] == DataErrorCodes.KeyExists:
                raise InvoiceExistsError from None

            raise

        return signed

    def __get_route_hints(self, amount_msat: int):
        if amount_msat is None or amount_msat is 0:
            raise NotImplementedError  # swaps always have the amount defined
        try:
            available_channels = self.__rpc.listpeerchannels()["channels"]
        except Exception as e:
            self.__logger.error(f"__get_route_hints rpc failed: {e}")
            return []

        suitable_channels = self.__filter_suitable_recv_chans(amount_msat,
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

    @staticmethod
    def __filter_suitable_recv_chans(inv_amount_msat: int, channels):
        suitable_channels = []
        # filter out channels that aren't private or available
        for channel in channels:
            if channel["private"] and channel["state"] is "CHANNELD_NORMAL":
                suitable_channels.append(channel)

        # sort by inbound capacity
        suitable_channels.sort(key=lambda x: x["receivable_msat"], reverse=True)

        # Filter out nodes that have low receive capacity compared to invoice amt.
        # Even with MPP, below a certain threshold, including these channels probably
        # hurts more than help, as they lead to many failed attempts for the sender.
        selected_channels = []
        running_sum = 0
        cutoff_factor = 0.2  # heuristic
        for channel in suitable_channels:
            recv_capacity = channel["receivable_msat"]
            chan_can_handle_payment_as_single_part = recv_capacity >= inv_amount_msat
            chan_small_compared_to_running_sum = recv_capacity < cutoff_factor * running_sum
            if not chan_can_handle_payment_as_single_part and chan_small_compared_to_running_sum:
                break
            running_sum += recv_capacity
            selected_channels.append(channel)
        return selected_channels[:15]

    def __get_payment_secret(self, payment_hash: bytes) -> bytes:
        return sha256(sha256(self.__payment_secret_key) + payment_hash)

    def add_payment_info_for_hold_invoice(self, payment_hash: bytes, amount_msat: int):
        pass

    def bundle_payments(self, payments: List[bytes]):
        pass

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

    # def get_payments(self, *, status=None) -> Mapping[bytes, List[HTLCWithStatus]]:
    #     out = defaultdict(list)
    #     for chan in self.channels.values():
    #         d = chan.get_payments(status=status)
    #         for payment_hash, plist in d.items():
    #             out[payment_hash] += plist
    #     return out

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


class InvalidInvoiceCreationError(Exception):
    pass

class InvalidPreimageFoundError(Exception):
    pass

class ClnRpcError(Exception):
    pass

class InvalidPreimageSavedError(Exception):
    pass

class DuplicateInvoiceCreationError(Exception):
    pass
