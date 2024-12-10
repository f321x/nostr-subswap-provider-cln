import attr
from attr import field
import time
from typing import List, Optional, Union, Dict, Any, Sequence, Set, Callable
import enum
from typing import Set, Callable

from .crypto import sha256
from .json_db import StoredObject, stored_in
from .lnutil import hex_to_bytes
from .utils import age, InvoiceError, format_satoshis
from .lnaddr import lndecode, LnAddr
from .bitcoin import COIN, TOTAL_COIN_SUPPLY_LIMIT_IN_BTC
from .transaction import PartialTxOutput
from .crypto import sha256d


# status of payment requests
PR_UNPAID   = 0     # if onchain: invoice amt not reached by txs in mempool+chain. if LN: invoice not paid.
PR_EXPIRED  = 1     # invoice is unpaid and expiry time reached
PR_UNKNOWN  = 2     # e.g. invoice not found
PR_PAID     = 3     # if onchain: paid and mined (1 conf). if LN: invoice is paid.
PR_INFLIGHT = 4     # only for LN. payment attempt in progress
PR_FAILED   = 5     # only for LN. we attempted to pay it, but all attempts failed
PR_ROUTING  = 6     # only for LN. *unused* atm.
PR_UNCONFIRMED = 7  # only onchain. invoice is satisfied but tx is not mined yet.
PR_BROADCASTING = 8    # onchain, tx is being broadcast
PR_BROADCAST    = 9    # onchain, tx was broadcast, is not yet in our history

pr_color = {
    PR_UNPAID:   (.7, .7, .7, 1),
    PR_PAID:     (.2, .9, .2, 1),
    PR_UNKNOWN:  (.7, .7, .7, 1),
    PR_EXPIRED:  (.9, .2, .2, 1),
    PR_INFLIGHT: (.9, .6, .3, 1),
    PR_FAILED:   (.9, .2, .2, 1),
    PR_ROUTING:  (.9, .6, .3, 1),
    PR_BROADCASTING:  (.9, .6, .3, 1),
    PR_BROADCAST:  (.9, .6, .3, 1),
    PR_UNCONFIRMED: (.9, .6, .3, 1),
}


def pr_tooltips():
    return {
        PR_UNPAID: 'Unpaid',
        PR_PAID: 'Paid',
        PR_UNKNOWN: 'Unknown',
        PR_EXPIRED: 'Expired',
        PR_INFLIGHT: 'In progress',
        PR_BROADCASTING: 'Broadcasting',
        PR_BROADCAST: 'Broadcast successfully',
        PR_FAILED: 'Failed',
        PR_ROUTING: 'Computing route...',
        PR_UNCONFIRMED: 'Unconfirmed',
    }


def pr_expiration_values():
    return {
        0: 'Never',
        10*60: '10 minutes',
        60*60: '1 hour',
        24*60*60: '1 day',
        7*24*60*60: '1 week',
    }


PR_DEFAULT_EXPIRATION_WHEN_CREATING = 24*60*60  # 1 day
assert PR_DEFAULT_EXPIRATION_WHEN_CREATING in pr_expiration_values()


def _decode_outputs(outputs) -> Optional[List[PartialTxOutput]]:
    if outputs is None:
        return None
    ret = []
    for output in outputs:
        if not isinstance(output, PartialTxOutput):
            output = PartialTxOutput.from_legacy_tuple(*output)
        ret.append(output)
    return ret


# hack: BOLT-11 is not really clear on what an expiry of 0 means.
# It probably interprets it as 0 seconds, so already expired...
# Our higher level invoices code however uses 0 for "never".
# Hence set some high expiration here
LN_EXPIRY_NEVER = 100 * 365 * 24 * 60 * 60  # 100 years



class HtlcState(enum.Enum):
    SETTLED = 1
    ACCEPTED = 2
    CANCELLED = 3

@attr.s(eq=False)
class Htlc:
    state: HtlcState = field()
    short_channel_id: str = field()
    channel_id: int = field()
    amount_msat: int = field()
    created_at: int = field()
    request_callback: Optional[Callable] = field()

    def __hash__(self):
        return hash(self.short_channel_id + str(self.channel_id) + str(self.created_at))

    def __eq__(self, other):
        if not isinstance(other, Htlc):
            return False
        return (self.short_channel_id == other.short_channel_id and
                self.channel_id == other.channel_id and
                self.amount_msat == other.amount_msat)

    @classmethod
    def from_cln_dict(cls: type['Htlc'], htlc_dict: dict[str, Any], request_callback: Callable) -> 'Htlc':
        return Htlc(
            state=HtlcState.ACCEPTED,
            short_channel_id=htlc_dict["short_channel_id"],
            channel_id=htlc_dict["id"],
            amount_msat=htlc_dict["amount_msat"],
            created_at=int(time.time()),
            request_callback=request_callback
        )

    def to_json(self):
        return {
            "_type": "Htlc",
            "state": self.state.value,
            "short_channel_id": self.short_channel_id,
            "channel_id": self.channel_id,
            "amount_msat": self.amount_msat,
            "created_at": self.created_at,
            # the request_callback is not serializable, we re-add it once CLN replayed the htlc after restart
        }

    @classmethod
    def from_json(cls, data: dict) -> 'Htlc':
        # Verify this is indeed Htlc data
        if data.get("_type") != "Htlc":
            raise ValueError("Invalid data type for Htlc")

        return cls(
            state=HtlcState(data["state"]),
            short_channel_id=data["short_channel_id"],
            channel_id=int(data["channel_id"]),
            amount_msat=int(data["amount_msat"]),
            created_at=int(data["created_at"]),
            request_callback=None
        )

    def add_new_htlc_callback(self, request_callback: Callable) -> None:
        self.request_callback = request_callback

    def fail(self) -> None:
        """Fail HTLC with incorrect_or_unknown_payment_details"""
        if not self.state == HtlcState.ACCEPTED:
            raise InvalidHtlcState("fail(): Htlc is not in ACCEPTED state, is: {}".format(self.state))
        assert(self.request_callback is not None), "Htlc has no callback set on fail"
        self.state = HtlcState.CANCELLED
        self.request_callback.set_result({"result": "fail", "failure_message": "400F"})

    def fail_timeout(self) -> None:
        """Fail HTLC with incorrect_or_unknown_payment_details"""
        if not self.state == HtlcState.ACCEPTED:
            raise InvalidHtlcState("fail(): Htlc is not in ACCEPTED state, is: {}".format(self.state))
        assert(self.request_callback is not None), "Htlc has no callback set on timeout"
        self.state = HtlcState.CANCELLED
        self.request_callback.set_result({"result": "fail", "failure_message": "0017"})  # mpp timeout

    def settle(self, preimage: bytes) -> None:
        """Settle HTLC with correct payment details"""
        if not self.state == HtlcState.ACCEPTED:
            raise InvalidHtlcState("Htlc is not in ACCEPTED state, is: {}".format(self.state))
        assert(self.request_callback is not None), (f"Htlc has no callback set on settle. "
                                                    f"Fix this or you lose your htlc.")
        self.state = HtlcState.SETTLED
        self.request_callback.set_result({"result": "resolve",
                                          "payment_key": preimage.hex()})

class InvalidHtlcState(Exception):
    pass

class InvoiceState(enum.Enum):
    SETTLED = 1
    FUNDED = 2
    UNFUNDED = 3
    FAILED = 4

# @attr.s(auto_attribs=True)
@stored_in("hold_invoices", _type="HoldInvoice")
class HoldInvoice:
    payment_hash: bytes
    bolt11: str
    amount_msat: int
    expiry: int
    incoming_htlcs: Set[Htlc]
    funding_status: InvoiceState
    created_at: int
    associated_invoice: Optional[bytes]

    def __init__(
        self,
        payment_hash: Union[bytes, str, Dict] = None,
        bolt11: str = None,
        amount_msat: int = None,
        expiry: int = None
    ):
        """This large init method is neccessary to allow for the JsonDB to instanciate the class with a dict."""
        if isinstance(payment_hash, dict):  # this is the case when we initiate JsonDB
            # Dictionary input
            data = payment_hash
            self.payment_hash = hex_to_bytes(data['payment_hash'])
            self.bolt11 = data['bolt11']
            self.amount_msat = data['amount_msat']
            self.expiry = data['expiry']
            self.incoming_htlcs = set(Htlc.from_json(htlc_json) for htlc_json in data.get('incoming_htlcs', set()))
            self.funding_status = InvoiceState(data['funding_status'])
            self.created_at = data['created_at']
            self.associated_invoice = hex_to_bytes(data['associated_invoice'])
        else:
            # Individual arguments
            self.payment_hash = hex_to_bytes(payment_hash)
            self.bolt11 = bolt11
            self.amount_msat = amount_msat
            self.expiry = expiry
            self.incoming_htlcs = set()
            self.funding_status = InvoiceState.UNFUNDED
            self.created_at = int(time.time())
            self.associated_invoice = None

    def attach_prepay_invoice(self, invoice_payment_hash: Union[str, bytes]) -> None:
        """Attach a prepay invoice payment hash to this HoldInvoice"""
        if self.associated_invoice is not None:
            raise DuplicateInvoiceCreationError("HoldInvoice already has a related PrepayInvoice")
        if isinstance(invoice_payment_hash, str):
            invoice_payment_hash = hex_to_bytes(invoice_payment_hash)
        self.associated_invoice = invoice_payment_hash

    def get_prepay_invoice(self) -> Optional[bytes]:
        """Returns the payment_hash of the associated prepay invoice"""
        return self.associated_invoice

    def find_htlc(self, new_htlc: Htlc) -> Optional[Htlc]:
        for stored_htlc in self.incoming_htlcs:
            if stored_htlc == new_htlc:
                return stored_htlc
        return None

    def is_fully_funded(self):
        """Returns True if the stored incoming htlcs sum up to the invoice amount or more."""
        return (sum(stored_htlc.amount_msat for stored_htlc in self.incoming_htlcs if stored_htlc.state in
                    [HtlcState.ACCEPTED, HtlcState.SETTLED])
                >= self.amount_msat)

    def cancel_all_htlcs(self) -> None:
        for stored_htlc in self.incoming_htlcs:
            if stored_htlc.state == HtlcState.ACCEPTED:
                stored_htlc.fail()
        self.funding_status = InvoiceState.FAILED

    def settle(self, preimage: Union[bytes, str]) -> None:
        """Settle the invoice with the given preimage"""
        if isinstance(preimage, str):
            preimage = hex_to_bytes(preimage)
        assert self.payment_hash == sha256(preimage), f"Invalid preimage in settle(): {preimage.hex()}"
        if not self.is_fully_funded():
            raise InsufficientFundedInvoiceError(f"HoldInvoice {self.payment_hash.hex()} is not fully funded")
        for stored_htlc in self.incoming_htlcs:
            if stored_htlc.state == HtlcState.ACCEPTED:
                stored_htlc.settle(preimage)
        self.funding_status = InvoiceState.SETTLED

    def to_json(self):
        return {
            "payment_hash": self.payment_hash.hex(),
            "bolt11": self.bolt11,
            "amount_msat": self.amount_msat,
            "expiry": self.expiry,
            "incoming_htlcs": [stored_htlc.to_json() for stored_htlc in self.incoming_htlcs],
            "funding_status": self.funding_status.value,
            "created_at": self.created_at,
            "associated_invoice": self.associated_invoice.hex() if self.associated_invoice else None
        }

class DuplicateInvoiceCreationError(Exception):
    pass

class InsufficientFundedInvoiceError(Exception):
    pass

@attr.s
class BaseInvoice(StoredObject):
    """
    Base class for Invoice and Request
    In the code, we use 'invoice' for outgoing payments, and 'request' for incoming payments.

    TODO this class is getting too complicated for "attrs"... maybe we should rewrite it without.
    """

    # mandatory fields
    amount_msat = attr.ib(  # can be '!' or None
        kw_only=True, on_setattr=attr.setters.validate)  # type: Optional[Union[int, str]]
    message = attr.ib(type=str, kw_only=True)
    time = attr.ib(  # timestamp of the invoice
        type=int, kw_only=True, validator=attr.validators.instance_of(int), on_setattr=attr.setters.validate)
    exp = attr.ib(  # expiration delay (relative). 0 means never
        type=int, kw_only=True, validator=attr.validators.instance_of(int), on_setattr=attr.setters.validate)

    # optional fields.
    # an request (incoming) can be satisfied onchain, using lightning or using a swap
    # an invoice (outgoing) is constructed from a source: bip21, bip70, lnaddr

    # onchain only
    outputs = attr.ib(kw_only=True, converter=_decode_outputs)  # type: Optional[List[PartialTxOutput]]
    height = attr.ib(  # only for receiving
        type=int, kw_only=True, validator=attr.validators.instance_of(int), on_setattr=attr.setters.validate)
    bip70 = attr.ib(type=str, kw_only=True)  # type: Optional[str]
    #bip70_requestor = attr.ib(type=str, kw_only=True)  # type: Optional[str]

    def is_lightning(self) -> bool:
        raise NotImplementedError()

    def get_address(self) -> Optional[str]:
        """returns the first address, to be displayed in GUI"""
        raise NotImplementedError()

    @property
    def rhash(self) -> str:
        raise NotImplementedError()

    def get_status_str(self, status):
        status_str = pr_tooltips()[status]
        if status == PR_UNPAID:
            if self.exp > 0 and self.exp != LN_EXPIRY_NEVER:
                expiration = self.get_expiration_date()
                status_str = 'Expires' + ' ' + age(expiration, include_seconds=True)
        return status_str

    def get_outputs(self) -> Sequence[PartialTxOutput]:
        outputs = self.outputs or []
        if not outputs:
            address = self.get_address()
            amount = self.get_amount_sat()
            if address and amount is not None:
                outputs = [PartialTxOutput.from_address_and_value(address, int(amount))]
        return outputs

    def get_expiration_date(self):
        # 0 means never
        return self.exp + self.time if self.exp else 0

    @staticmethod
    def _get_cur_time():  # for unit tests
        return time.time()

    def has_expired(self) -> bool:
        exp = self.get_expiration_date()
        return bool(exp) and exp < self._get_cur_time()

    def get_amount_msat(self) -> Union[int, str, None]:
        return self.amount_msat

    def get_time(self):
        return self.time

    def get_message(self):
        return self.message

    def get_amount_sat(self) -> Union[int, str, None]:
        """
        Returns an integer satoshi amount, or '!' or None.
        Callers who need msat precision should call get_amount_msat()
        """
        amount_msat = self.amount_msat
        if amount_msat in [None, "!"]:
            return amount_msat
        return int(amount_msat // 1000)

    def set_amount_msat(self, amount_msat: Union[int, str]) -> None:
        """The GUI uses this to fill the amount for a zero-amount invoice."""
        if amount_msat == "!":
            amount_sat = amount_msat
        else:
            assert isinstance(amount_msat, int), f"{amount_msat=!r}"
            assert amount_msat >= 0, amount_msat
            amount_sat = (amount_msat // 1000) + int(amount_msat % 1000 > 0)  # round up
        if outputs := self.outputs:
            assert len(self.outputs) == 1, len(self.outputs)
            self.outputs = [PartialTxOutput(scriptpubkey=outputs[0].scriptpubkey, value=amount_sat)]
        self.amount_msat = amount_msat

    @amount_msat.validator
    def _validate_amount(self, attribute, value):
        if value is None:
            return
        if isinstance(value, int):
            if not (0 <= value <= TOTAL_COIN_SUPPLY_LIMIT_IN_BTC * COIN * 1000):
                raise InvoiceError(f"amount is out-of-bounds: {value!r} msat")
        elif isinstance(value, str):
            if value != '!':
                raise InvoiceError(f"unexpected amount: {value!r}")
        else:
            raise InvoiceError(f"unexpected amount: {value!r}")

    @classmethod
    def from_bech32(cls, invoice: str) -> 'Invoice':
        """Constructs Invoice object from BOLT-11 string.
        Might raise InvoiceError.
        """
        try:
            lnaddr = lndecode(invoice)
        except Exception as e:
            raise InvoiceError(e) from e
        amount_msat = lnaddr.get_amount_msat()
        timestamp = lnaddr.date
        exp_delay = lnaddr.get_expiry()
        message = lnaddr.get_description()
        return Invoice(
            message=message,
            amount_msat=amount_msat,
            time=timestamp,
            exp=exp_delay,
            outputs=None,
            bip70=None,
            height=0,
            lightning_invoice=invoice,
        )

    @classmethod
    def from_bip70_payreq(cls, pr: 'PaymentRequest', *, height: int = 0) -> 'Invoice':
        return Invoice(
            amount_msat=pr.get_amount()*1000,
            message=pr.get_memo(),
            time=pr.get_time(),
            exp=pr.get_expiration_date() - pr.get_time(),
            outputs=pr.get_outputs(),
            bip70=pr.raw.hex(),
            height=height,
            lightning_invoice=None,
        )

    def get_id(self) -> str:
        if self.is_lightning():
            return self.rhash
        else:  # on-chain
            return get_id_from_onchain_outputs(outputs=self.get_outputs(), timestamp=self.time)

    def as_dict(self, status):
        d = {
            'is_lightning': self.is_lightning(),
            'amount_BTC': format_satoshis(self.get_amount_sat()),
            'message': self.message,
            'timestamp': self.get_time(),
            'expiry': self.exp,
            'status': status,
            'status_str': self.get_status_str(status),
            'id': self.get_id(),
            'amount_sat': self.get_amount_sat(),
        }
        if self.is_lightning():
            d['amount_msat'] = self.get_amount_msat()
        return d


@stored_in('invoices')
@attr.s
class Invoice(BaseInvoice):
    lightning_invoice = attr.ib(type=str, kw_only=True)  # type: Optional[str]
    __lnaddr = None
    _broadcasting_status = None # can be None or PR_BROADCASTING or PR_BROADCAST

    def is_lightning(self):
        return self.lightning_invoice is not None

    def get_broadcasting_status(self):
        return self._broadcasting_status

    def get_address(self) -> Optional[str]:
        address = None
        if self.outputs:
            address = self.outputs[0].address if len(self.outputs) > 0 else None
        if not address and self.is_lightning():
            address = self._lnaddr.get_fallback_address() or None
        return address

    @property
    def _lnaddr(self) -> LnAddr:
        if self.__lnaddr is None:
            self.__lnaddr = lndecode(self.lightning_invoice)
        return self.__lnaddr

    @property
    def rhash(self) -> str:
        assert self.is_lightning()
        return self._lnaddr.paymenthash.hex()

    @lightning_invoice.validator
    def _validate_invoice_str(self, attribute, value):
        if value is not None:
            lnaddr = lndecode(value)  # this checks the str can be decoded
            self.__lnaddr = lnaddr    # save it, just to avoid having to recompute later

    def can_be_paid_onchain(self) -> bool:
        if self.is_lightning():
            return bool(self._lnaddr.get_fallback_address()) or (bool(self.outputs))
        else:
            return True

    def to_debug_json(self) -> Dict[str, Any]:
        d = self.to_json()
        d["lnaddr"] = self._lnaddr.to_debug_json()
        return d


def get_id_from_onchain_outputs(outputs: Sequence[PartialTxOutput], *, timestamp: int) -> str:
    outputs_str = "\n".join(f"{txout.scriptpubkey.hex()}, {txout.value}" for txout in outputs)
    return sha256d(outputs_str + "%d" % timestamp).hex()[0:10]
