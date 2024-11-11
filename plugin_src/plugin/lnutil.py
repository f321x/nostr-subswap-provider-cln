# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
import time
from enum import IntFlag
from datetime import datetime, timezone
import enum
# import json
# from collections import defaultdict
from typing import Tuple, Optional, Any, Callable, Set
# import re
# import sys

import electrum_ecc as ecc
# from electrum_ecc import CURVE_ORDER, ecdsa_sig64_from_der_sig, ECPubkey, string_to_number
import attr
from attrs import field

from .crypto import sha256
from .json_db import stored_in
# from aiorpcx import NetAddress
#
# from .util import bfh, UserFacingException
from .utils import list_enabled_bits
#
# from .crypto import sha256, pw_decode_with_version_and_mac
# from .transaction import (Transaction, PartialTransaction, PartialTxInput, TxOutpoint,
#                           PartialTxOutput, opcodes)
# from . import crypto, transaction
# from . import descriptor
# from plugin.stripped_files.bitcoin_old import (redeem_script_to_address, address_to_script,
#                                                construct_witness, construct_script)
# from . import segwit_addr
# from .i18n import _
# from .lnaddr import lndecode
# from .bip32 import BIP32Node, BIP32_PRIME
# from .transaction import BCDataStream, OPPushDataGeneric
from .globals import get_plugin_logger


# if TYPE_CHECKING:
#     from .lnchannel import Channel, AbstractChannel
#     from .lnrouter import LNPaymentRoute
#     from .lnonion import OnionRoutingFailure
#     from .simple_config import SimpleConfig


_logger = get_plugin_logger()


# defined in BOLT-03:
HTLC_TIMEOUT_WEIGHT = 663
HTLC_SUCCESS_WEIGHT = 703
COMMITMENT_TX_WEIGHT = 724
HTLC_OUTPUT_WEIGHT = 172

LN_MAX_FUNDING_SAT_LEGACY = pow(2, 24) - 1
DUST_LIMIT_MAX = 1000


# from .json_db import StoredObject, stored_in, stored_as


# def channel_id_from_funding_tx(funding_txid: str, funding_index: int) -> Tuple[bytes, bytes]:
#     funding_txid_bytes = bytes.fromhex(funding_txid)[::-1]
#     i = int.from_bytes(funding_txid_bytes, 'big') ^ funding_index
#     return i.to_bytes(32, 'big'), funding_txid_bytes

hex_to_bytes = lambda v: v if isinstance(v, bytes) else bytes.fromhex(v) if v is not None else None
bytes_to_hex = lambda v: repr(v.hex()) if v is not None else None
json_to_keypair = lambda v: v if isinstance(v, OnlyPubkeyKeypair) else Keypair(**v) if len(v)==2 else OnlyPubkeyKeypair(**v)


def serialize_htlc_key(scid: bytes, htlc_id: int) -> str:
    return scid.hex() + ':%d'%htlc_id


def deserialize_htlc_key(htlc_key: str) -> Tuple[bytes, int]:
    scid, htlc_id = htlc_key.split(':')
    return bytes.fromhex(scid), int(htlc_id)

def filter_suitable_recv_chans(inv_amount_msat: int, channels):
    suitable_channels = []
    # filter out channels that aren't private or available
    for channel in channels:
        if channel["private"] and channel["state"] == "CHANNELD_NORMAL":
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

@attr.s
class OnlyPubkeyKeypair:
    pubkey = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)

@attr.s
class Keypair(OnlyPubkeyKeypair):
    privkey = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)

class HtlcState(enum.Enum):
    SETTLED = 1
    ACCEPTED = 2
    CANCELLED = 3

@attr.s
class Htlc:
    state: HtlcState = field()
    short_channel_id: str = field()
    channel_id: int = field()
    amount_msat: int = field()
    created_at: datetime = field()
    request_callback: Optional[Callable] = field()

    @classmethod
    def from_dict(cls: type['Htlc'], htlc_dict: dict[str, Any], request_callback: Callable) -> 'Htlc':
        return Htlc(
            state=HtlcState.ACCEPTED,
            short_channel_id=htlc_dict["short_channel_id"],
            channel_id=htlc_dict["id"],
            amount_msat=htlc_dict["amount_msat"],
            created_at=datetime.now(tz=timezone.utc),
            request_callback=request_callback
        )

    def to_json(self):
        return {
            "_type": "Htlc",
            "state": self.state.value,
            "short_channel_id": self.short_channel_id,
            "channel_id": self.channel_id,
            "amount_msat": self.amount_msat,
            "created_at": self.created_at.isoformat(),
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
            channel_id=data["channel_id"],
            amount_msat=data["amount_msat"],
            created_at=datetime.fromisoformat(data["created_at"]),
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
        assert(self.request_callback is not None), "Htlc has no callback set on settle"
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

@stored_in("hold_invoices")
@attr.s(auto_attribs=True)
class HoldInvoice:
    payment_hash: bytes
    bolt11: str
    amount_msat: int
    expiry: int
    incoming_htlcs: Set[Htlc] = attr.Factory(set)
    funding_status: InvoiceState = attr.Factory(lambda: InvoiceState.UNFUNDED)
    created_at: int = attr.Factory(lambda: int(time.time()))
    associated_invoice: bytes = attr.Factory(lambda: None)  # payment_hash of the related prepay invoice

    def attach_prepay_invoice(self, invoice_payment_hash: bytes) -> None:
        """Attach a prepay invoice payment hash to this HoldInvoice"""
        if self.associated_invoice is not None:
            raise DuplicateInvoiceCreationError("HoldInvoice already has a related PrepayInvoice")
        self.associated_invoice = invoice_payment_hash

    def get_prepay_invoice(self) -> Optional[bytes]:
        """Returns the payment_hash of the associated prepay invoice"""
        return self.associated_invoice

    def find_htlc(self, scid: str, channel_id: int) -> Optional[Htlc]:
        for stored_htlc in self.incoming_htlcs:
            if stored_htlc.short_channel_id == scid and stored_htlc.channel_id == channel_id:
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

    def cancel_expired_htlcs(self) -> bool:
        """Cancel all expired htlcs and return True if changes need to be saved"""
        changes = False
        for stored_htlc in self.incoming_htlcs:
            if stored_htlc.state == HtlcState.ACCEPTED and (datetime.now(timezone.utc) -
                                                            stored_htlc.created_at).total_seconds() > self.expiry:
                changes = True
                stored_htlc.fail_timeout()
        if changes and self.funding_status == InvoiceState.FUNDED and not self.is_fully_funded():
            # set invoice to unfunded again in case it was already set funded and we are now below the threshold
            self.funding_status = InvoiceState.UNFUNDED
        return changes

    def settle(self, preimage: bytes) -> None:
        assert preimage == sha256(self.payment_hash), f"Invalid preimage in settle(): {preimage.hex()}"
        if not self.is_fully_funded():
            raise InsufficientFundedInvoiceError(f"HoldInvoice {self.payment_hash} is not fully funded")
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

    @classmethod
    def from_json(cls, data: dict):
        return cls(
            payment_hash=bytes.fromhex(data["payment_hash"]),
            bolt11=data["bolt11"],
            amount_msat=data["amount_msat"],
            expiry=data["expiry"],
            incoming_htlcs={Htlc.from_json(restored_htlc) for restored_htlc in data["incoming_htlcs"]},
            funding_status=InvoiceState(data["funding_status"]),
            created_at=data["created_at"],
            associated_invoice=bytes.fromhex(data["associated_invoice"]) if data["associated_invoice"] else None
        )

class DuplicateInvoiceCreationError(Exception):
    pass

class InsufficientFundedInvoiceError(Exception):
    pass

# @attr.s
# class ChannelConfig(StoredObject):
#     # shared channel config fields
#     payment_basepoint = attr.ib(type=OnlyPubkeyKeypair, converter=json_to_keypair)
#     multisig_key = attr.ib(type=OnlyPubkeyKeypair, converter=json_to_keypair)
#     htlc_basepoint = attr.ib(type=OnlyPubkeyKeypair, converter=json_to_keypair)
#     delayed_basepoint = attr.ib(type=OnlyPubkeyKeypair, converter=json_to_keypair)
#     revocation_basepoint = attr.ib(type=OnlyPubkeyKeypair, converter=json_to_keypair)
#     to_self_delay = attr.ib(type=int)  # applies to OTHER ctx
#     dust_limit_sat = attr.ib(type=int)  # applies to SAME ctx
#     max_htlc_value_in_flight_msat = attr.ib(type=int)  # max val of INCOMING htlcs
#     max_accepted_htlcs = attr.ib(type=int)  # max num of INCOMING htlcs
#     initial_msat = attr.ib(type=int)
#     reserve_sat = attr.ib(type=int)  # applies to OTHER ctx
#     htlc_minimum_msat = attr.ib(type=int)  # smallest value for INCOMING htlc
#     upfront_shutdown_script = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)
#     announcement_node_sig = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)
#     announcement_bitcoin_sig = attr.ib(type=bytes, converter=hex_to_bytes, repr=bytes_to_hex)
#
#     def validate_params(self, *, funding_sat: int, config: 'SimpleConfig', peer_features: 'LnFeatures') -> None:
#         conf_name = type(self).__name__
#         for key in (
#                 self.payment_basepoint,
#                 self.multisig_key,
#                 self.htlc_basepoint,
#                 self.delayed_basepoint,
#                 self.revocation_basepoint
#         ):
#             if not (len(key.pubkey) == 33 and ecc.ECPubkey.is_pubkey_bytes(key.pubkey)):
#                 raise Exception(f"{conf_name}. invalid pubkey in channel config")
#         if funding_sat < MIN_FUNDING_SAT:
#             raise Exception(f"funding_sat too low: {funding_sat} sat < {MIN_FUNDING_SAT}")
#         if not peer_features.supports(LnFeatures.OPTION_SUPPORT_LARGE_CHANNEL_OPT):
#             # MUST set funding_satoshis to less than 2^24 satoshi
#             if funding_sat > LN_MAX_FUNDING_SAT_LEGACY:
#                 raise Exception(f"funding_sat too high: {funding_sat} sat > {LN_MAX_FUNDING_SAT_LEGACY} (legacy limit)")
#         if funding_sat > config.LIGHTNING_MAX_FUNDING_SAT:
#             raise Exception(f"funding_sat too high: {funding_sat} sat > {config.LIGHTNING_MAX_FUNDING_SAT} (config setting)")
#         # MUST set push_msat to equal or less than 1000 * funding_satoshis
#         if not (0 <= self.initial_msat <= 1000 * funding_sat):
#             raise Exception(f"{conf_name}. insane initial_msat={self.initial_msat}. (funding_sat={funding_sat})")
#         if self.reserve_sat < self.dust_limit_sat:
#             raise Exception(f"{conf_name}. MUST set channel_reserve_satoshis greater than or equal to dust_limit_satoshis")
#         if self.dust_limit_sat < bitcoin.DUST_LIMIT_UNKNOWN_SEGWIT:
#             raise Exception(f"{conf_name}. dust limit too low: {self.dust_limit_sat} sat")
#         if self.dust_limit_sat > DUST_LIMIT_MAX:
#             raise Exception(f"{conf_name}. dust limit too high: {self.dust_limit_sat} sat")
#         if self.reserve_sat > funding_sat // 100:
#             raise Exception(f"{conf_name}. reserve too high: {self.reserve_sat}, funding_sat: {funding_sat}")
#         if self.htlc_minimum_msat > 1_000:
#             raise Exception(f"{conf_name}. htlc_minimum_msat too high: {self.htlc_minimum_msat} msat")
#         HTLC_MINIMUM_MSAT_MIN = 0  # should be at least 1 really, but apparently some nodes are sending zero...
#         if self.htlc_minimum_msat < HTLC_MINIMUM_MSAT_MIN:
#             raise Exception(f"{conf_name}. htlc_minimum_msat too low: {self.htlc_minimum_msat} msat < {HTLC_MINIMUM_MSAT_MIN}")
#         if self.max_accepted_htlcs < 5:
#             raise Exception(f"{conf_name}. max_accepted_htlcs too low: {self.max_accepted_htlcs}")
#         if self.max_accepted_htlcs > 483:
#             raise Exception(f"{conf_name}. max_accepted_htlcs too high: {self.max_accepted_htlcs}")
#         if self.to_self_delay > MAXIMUM_REMOTE_TO_SELF_DELAY_ACCEPTED:
#             raise Exception(f"{conf_name}. to_self_delay too high: {self.to_self_delay} > {MAXIMUM_REMOTE_TO_SELF_DELAY_ACCEPTED}")
#         if self.max_htlc_value_in_flight_msat < min(1000 * funding_sat, 100_000_000):
#             raise Exception(f"{conf_name}. max_htlc_value_in_flight_msat is too small: {self.max_htlc_value_in_flight_msat}")
#
#     @classmethod
#     def cross_validate_params(
#             cls,
#             *,
#             local_config: 'LocalConfig',
#             remote_config: 'RemoteConfig',
#             funding_sat: int,
#             is_local_initiator: bool,  # whether we are the funder
#             initial_feerate_per_kw: int,
#             config: 'SimpleConfig',
#             peer_features: 'LnFeatures',
#     ) -> None:
#         # first we validate the configs separately
#         local_config.validate_params(funding_sat=funding_sat, config=config, peer_features=peer_features)
#         remote_config.validate_params(funding_sat=funding_sat, config=config, peer_features=peer_features)
#         # now do tests that need access to both configs
#         if is_local_initiator:

# class LnFeatureContexts(enum.Flag):
#     INIT = enum.auto()
#     NODE_ANN = enum.auto()
#     CHAN_ANN_AS_IS = enum.auto()
#     CHAN_ANN_ALWAYS_ODD = enum.auto()
#     CHAN_ANN_ALWAYS_EVEN = enum.auto()
#     INVOICE = enum.auto()
#
# LNFC = LnFeatureContexts

# _ln_feature_direct_dependencies = defaultdict(set)  # type: Dict[LnFeatures, Set[LnFeatures]]
_ln_feature_contexts = {}  # type: # Dict[LnFeatures, LnFeatureContexts]

class LnFeatures(IntFlag):
    OPTION_DATA_LOSS_PROTECT_REQ = 1 << 0
    OPTION_DATA_LOSS_PROTECT_OPT = 1 << 1

    INITIAL_ROUTING_SYNC = 1 << 3

    OPTION_UPFRONT_SHUTDOWN_SCRIPT_REQ = 1 << 4
    OPTION_UPFRONT_SHUTDOWN_SCRIPT_OPT = 1 << 5

    GOSSIP_QUERIES_REQ = 1 << 6
    GOSSIP_QUERIES_OPT = 1 << 7

    VAR_ONION_REQ = 1 << 8
    VAR_ONION_OPT = 1 << 9

    GOSSIP_QUERIES_EX_REQ = 1 << 10
    GOSSIP_QUERIES_EX_OPT = 1 << 11

    OPTION_STATIC_REMOTEKEY_REQ = 1 << 12
    OPTION_STATIC_REMOTEKEY_OPT = 1 << 13

    PAYMENT_SECRET_REQ = 1 << 14
    PAYMENT_SECRET_OPT = 1 << 15

    BASIC_MPP_REQ = 1 << 16
    BASIC_MPP_OPT = 1 << 17

    OPTION_SUPPORT_LARGE_CHANNEL_REQ = 1 << 18
    OPTION_SUPPORT_LARGE_CHANNEL_OPT = 1 << 19

    # Temporary number.
    OPTION_TRAMPOLINE_ROUTING_REQ_ECLAIR = 1 << 148
    OPTION_TRAMPOLINE_ROUTING_OPT_ECLAIR = 1 << 149

    # We use a different bit because Phoenix cannot do end-to-end multi-trampoline routes
    OPTION_TRAMPOLINE_ROUTING_REQ_ELECTRUM = 1 << 150
    OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM = 1 << 151

    OPTION_SHUTDOWN_ANYSEGWIT_REQ = 1 << 26
    OPTION_SHUTDOWN_ANYSEGWIT_OPT = 1 << 27

    OPTION_CHANNEL_TYPE_REQ = 1 << 44
    OPTION_CHANNEL_TYPE_OPT = 1 << 45

    OPTION_SCID_ALIAS_REQ = 1 << 46
    OPTION_SCID_ALIAS_OPT = 1 << 47

    OPTION_ZEROCONF_REQ = 1 << 50
    OPTION_ZEROCONF_OPT = 1 << 51

    # def validate_transitive_dependencies(self) -> bool:
    #     # for all even bit set, set corresponding odd bit:
    #     features = self  # copy
    #     flags = list_enabled_bits(features)
    #     for flag in flags:
    #         if flag % 2 == 0:
    #             features |= 1 << get_ln_flag_pair_of_bit(flag)
    #     # Check dependencies. We only check that the direct dependencies of each flag set
    #     # are satisfied: this implies that transitive dependencies are also satisfied.
    #     flags = list_enabled_bits(features)
    #     for flag in flags:
    #         for dependency in _ln_feature_direct_dependencies[1 << flag]:
    #             if not (dependency & features):
    #                 return False
    #     return True
    #
    # def for_init_message(self) -> 'LnFeatures':
    #     features = LnFeatures(0)
    #     for flag in list_enabled_bits(self):
    #         if LnFeatureContexts.INIT & _ln_feature_contexts[1 << flag]:
    #             features |= (1 << flag)
    #     return features
    #
    # def for_node_announcement(self) -> 'LnFeatures':
    #     features = LnFeatures(0)
    #     for flag in list_enabled_bits(self):
    #         if LnFeatureContexts.NODE_ANN & _ln_feature_contexts[1 << flag]:
    #             features |= (1 << flag)
    #     return features

    # def for_invoice(self) -> 'LnFeatures':
    #     features = LnFeatures(0)
    #     for flag in list_enabled_bits(self):
    #         if LnFeatureContexts.INVOICE & _ln_feature_contexts[1 << flag]:
    #             features |= (1 << flag)
    #     return features

    # def for_channel_announcement(self) -> 'LnFeatures':
    #     features = LnFeatures(0)
    #     for flag in list_enabled_bits(self):
    #         ctxs = _ln_feature_contexts[1 << flag]
    #         if LnFeatureContexts.CHAN_ANN_AS_IS & ctxs:
    #             features |= (1 << flag)
    #         elif LnFeatureContexts.CHAN_ANN_ALWAYS_EVEN & ctxs:
    #             if flag % 2 == 0:
    #                 features |= (1 << flag)
    #         elif LnFeatureContexts.CHAN_ANN_ALWAYS_ODD & ctxs:
    #             if flag % 2 == 0:
    #                 flag = get_ln_flag_pair_of_bit(flag)
    #             features |= (1 << flag)
    #     return features
    #
    # def supports(self, feature: 'LnFeatures') -> bool:
    #     """Returns whether given feature is enabled.
    #
    #     Helper function that tries to hide the complexity of even/odd bits.
    #     For example, instead of:
    #       bool(myfeatures & LnFeatures.VAR_ONION_OPT or myfeatures & LnFeatures.VAR_ONION_REQ)
    #     you can do:
    #       myfeatures.supports(LnFeatures.VAR_ONION_OPT)
    #     """
    #     if (1 << (feature.bit_length() - 1)) != feature:
    #         raise ValueError(f"'feature' cannot be a combination of features: {feature}")
    #     if feature.bit_length() % 2 == 0:  # feature is OPT
    #         feature_other = feature >> 1
    #     else:  # feature is REQ
    #         feature_other = feature << 1
    #     return (self & feature != 0) or (self & feature_other != 0)
    #
    # def get_names(self) -> Sequence[str]:
    #     r = []
    #     for flag in list_enabled_bits(self):
    #         feature_name = LnFeatures(1 << flag).name
    #         r.append(feature_name or f"bit_{flag}")
    #     return r

    if hasattr(IntFlag, "_numeric_repr_"):  # python 3.11+
        # performance improvement (avoid base2<->base10), see #8403
        _numeric_repr_ = hex

    def __repr__(self):
        # performance improvement (avoid base2<->base10), see #8403
        return f"<{self._name_}: {hex(self._value_)}>"

    def __str__(self):
        # performance improvement (avoid base2<->base10), see #8403
        return hex(self._value_)


# @stored_as('channel_type', _type=None)
# class ChannelType(IntFlag):
#     OPTION_LEGACY_CHANNEL = 0
#     OPTION_STATIC_REMOTEKEY = 1 << 12
#     OPTION_ANCHOR_OUTPUTS = 1 << 20
#     OPTION_ANCHORS_ZERO_FEE_HTLC_TX = 1 << 22
#     OPTION_SCID_ALIAS = 1 << 46
#     OPTION_ZEROCONF = 1 << 50
#
#     def discard_unknown_and_check(self):
#         """Discards unknown flags and checks flag combination."""
#         flags = list_enabled_bits(self)
#         known_channel_types = []
#         for flag in flags:
#             channel_type = ChannelType(1 << flag)
#             if channel_type.name:
#                 known_channel_types.append(channel_type)
#         final_channel_type = known_channel_types[0]
#         for channel_type in known_channel_types[1:]:
#             final_channel_type |= channel_type
#
#         final_channel_type.check_combinations()
#         return final_channel_type
#
#     def check_combinations(self):
#         basic_type = self & ~(ChannelType.OPTION_SCID_ALIAS | ChannelType.OPTION_ZEROCONF)
#         if basic_type not in [
#                 ChannelType.OPTION_STATIC_REMOTEKEY,
#                 ChannelType.OPTION_ANCHOR_OUTPUTS | ChannelType.OPTION_STATIC_REMOTEKEY,
#                 ChannelType.OPTION_ANCHORS_ZERO_FEE_HTLC_TX | ChannelType.OPTION_STATIC_REMOTEKEY
#         ]:
#             raise ValueError("Channel type is not a valid flag combination.")
#
#     def complies_with_features(self, features: LnFeatures) -> bool:
#         flags = list_enabled_bits(self)
#         complies = True
#         for flag in flags:
#             feature = LnFeatures(1 << flag)
#             complies &= features.supports(feature)
#         return complies
#
#     def to_bytes_minimal(self):
#         # MUST use the smallest bitmap possible to represent the channel type.
#         bit_length =self.value.bit_length()
#         byte_length = bit_length // 8 + int(bool(bit_length % 8))
#         return self.to_bytes(byte_length, byteorder='big')
#
#     @property
#     def name_minimal(self):
#         if self.name:
#             return self.name.replace('OPTION_', '')
#         else:
#             return str(self)
#
#
# del LNFC  # name is ambiguous without context
#
# # features that are actually implemented and understood in our codebase:
# # (note: this is not what we send in e.g. init!)
# # (note: specify both OPT and REQ here)
# LN_FEATURES_IMPLEMENTED = (
#         LnFeatures(0)
#         | LnFeatures.OPTION_DATA_LOSS_PROTECT_OPT | LnFeatures.OPTION_DATA_LOSS_PROTECT_REQ
#         | LnFeatures.GOSSIP_QUERIES_OPT | LnFeatures.GOSSIP_QUERIES_REQ
#         | LnFeatures.OPTION_STATIC_REMOTEKEY_OPT | LnFeatures.OPTION_STATIC_REMOTEKEY_REQ
#         | LnFeatures.VAR_ONION_OPT | LnFeatures.VAR_ONION_REQ
#         | LnFeatures.PAYMENT_SECRET_OPT | LnFeatures.PAYMENT_SECRET_REQ
#         | LnFeatures.BASIC_MPP_OPT | LnFeatures.BASIC_MPP_REQ
#         | LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM | LnFeatures.OPTION_TRAMPOLINE_ROUTING_REQ_ELECTRUM
#         | LnFeatures.OPTION_SHUTDOWN_ANYSEGWIT_OPT | LnFeatures.OPTION_SHUTDOWN_ANYSEGWIT_REQ
#         | LnFeatures.OPTION_CHANNEL_TYPE_OPT | LnFeatures.OPTION_CHANNEL_TYPE_REQ
#         | LnFeatures.OPTION_SCID_ALIAS_OPT | LnFeatures.OPTION_SCID_ALIAS_REQ
# )
#
#
# def get_ln_flag_pair_of_bit(flag_bit: int) -> int:
#     """Ln Feature flags are assigned in pairs, one even, one odd. See BOLT-09.
#     Return the other flag from the pair.
#     e.g. 6 -> 7
#     e.g. 7 -> 6
#     """
#     if flag_bit % 2 == 0:
#         return flag_bit + 1
#     else:
#         return flag_bit - 1
#
#
#
# class IncompatibleOrInsaneFeatures(Exception): pass
# class UnknownEvenFeatureBits(IncompatibleOrInsaneFeatures): pass
# class IncompatibleLightningFeatures(IncompatibleOrInsaneFeatures): pass
#
#
# def ln_compare_features(our_features: 'LnFeatures', their_features: int) -> 'LnFeatures':
#     """Returns negotiated features.
#     Raises IncompatibleLightningFeatures if incompatible.
#     """
#     our_flags = set(list_enabled_bits(our_features))
#     their_flags = set(list_enabled_bits(their_features))
#     # check that they have our required features, and disable the optional features they don't have
#     for flag in our_flags:
#         if flag not in their_flags and get_ln_flag_pair_of_bit(flag) not in their_flags:
#             # they don't have this feature we wanted :(
#             if flag % 2 == 0:  # even flags are compulsory
#                 raise IncompatibleLightningFeatures(f"remote does not support {LnFeatures(1 << flag)!r}")
#             our_features ^= 1 << flag  # disable flag
#         else:
#             # They too have this flag.
#             # For easier feature-bit-testing, if this is an even flag, we also
#             # set the corresponding odd flag now.
#             if flag % 2 == 0 and our_features & (1 << flag):
#                 our_features |= 1 << get_ln_flag_pair_of_bit(flag)
#     # check that we have their required features
#     for flag in their_flags:
#         if flag not in our_flags and get_ln_flag_pair_of_bit(flag) not in our_flags:
#             # we don't have this feature they wanted :(
#             if flag % 2 == 0:  # even flags are compulsory
#                 raise IncompatibleLightningFeatures(f"remote wanted feature we don't have: {LnFeatures(1 << flag)!r}")
#     return our_features
#
#
# if hasattr(sys, "get_int_max_str_digits"):
#     # check that the user or other library has not lowered the limit (from default)
#     assert sys.get_int_max_str_digits() >= 4300, f"sys.get_int_max_str_digits() too low: {sys.get_int_max_str_digits()}"
#
#
# def validate_features(features: int) -> LnFeatures:
#     """Raises IncompatibleOrInsaneFeatures if
#     - a mandatory feature is listed that we don't recognize, or
#     - the features are inconsistent
#     For convenience, returns the parsed features.
#     """
#     if features.bit_length() > 10_000:
#         # This is an implementation-specific limit for how high feature bits we allow.
#         # Needed as LnFeatures subclasses IntFlag, and uses ints internally.
#         # See https://docs.python.org/3/library/stdtypes.html#integer-string-conversion-length-limitation
#         raise IncompatibleOrInsaneFeatures(f"features bitvector too large: {features.bit_length()=} > 10_000")
#     features = LnFeatures(features)
#     enabled_features = list_enabled_bits(features)
#     for fbit in enabled_features:
#         if (1 << fbit) & LN_FEATURES_IMPLEMENTED == 0 and fbit % 2 == 0:
#             raise UnknownEvenFeatureBits(fbit)
#     if not features.validate_transitive_dependencies():
#         raise IncompatibleOrInsaneFeatures(f"not all transitive dependencies are set. "
#                                            f"features={features}")
#     return features
#
#
# def derive_payment_secret_from_payment_preimage(payment_preimage: bytes) -> bytes:
#     """Returns secret to be put into invoice.
#     Derivation is deterministic, based on the preimage.
#     Crucially the payment_hash must be derived in an independent way from this.
#     """
#     # Note that this could be random data too, but then we would need to store it.
#     # We derive it identically to clightning, so that we cannot be distinguished:
#     # https://github.com/ElementsProject/lightning/blob/faac4b28adee5221e83787d64cd5d30b16b62097/lightningd/invoice.c#L115
#     modified = bytearray(payment_preimage)
#     modified[0] ^= 1
#     return sha256(bytes(modified))
#
#
# class LNPeerAddr:
#     # note: while not programmatically enforced, this class is meant to be *immutable*
#
#     def __init__(self, host: str, port: int, pubkey: bytes):
#         assert isinstance(host, str), repr(host)
#         assert isinstance(port, int), repr(port)
#         assert isinstance(pubkey, bytes), repr(pubkey)
#         try:
#             net_addr = NetAddress(host, port)  # this validates host and port
#         except Exception as e:
#             raise ValueError(f"cannot construct LNPeerAddr: invalid host or port (host={host}, port={port})") from e
#         # note: not validating pubkey as it would be too expensive:
#         # if not ECPubkey.is_pubkey_bytes(pubkey): raise ValueError()
#         self.host = host
#         self.port = port
#         self.pubkey = pubkey
#         self._net_addr = net_addr
#
#     def __str__(self):
#         return '{}@{}'.format(self.pubkey.hex(), self.net_addr_str())
#
#     @classmethod
#     def from_str(cls, s):
#         node_id, rest = extract_nodeid(s)
#         host, port = split_host_port(rest)
#         return LNPeerAddr(host, int(port), node_id)
#
#     def __repr__(self):
#         return f'<LNPeerAddr host={self.host} port={self.port} pubkey={self.pubkey.hex()}>'
#
#     def net_addr(self) -> NetAddress:
#         return self._net_addr
#
#     def net_addr_str(self) -> str:
#         return str(self._net_addr)
#
#     def __eq__(self, other):
#         if not isinstance(other, LNPeerAddr):
#             return False
#         return (self.host == other.host
#                 and self.port == other.port
#                 and self.pubkey == other.pubkey)
#
#     def __ne__(self, other):
#         return not (self == other)
#
#     def __hash__(self):
#         return hash((self.host, self.port, self.pubkey))
#
#
# def get_compressed_pubkey_from_bech32(bech32_pubkey: str) -> bytes:
#     decoded_bech32 = segwit_addr.bech32_decode(bech32_pubkey)
#     hrp = decoded_bech32.hrp
#     data_5bits = decoded_bech32.data
#     if decoded_bech32.encoding is None:
#         raise ValueError("Bad bech32 checksum")
#     if decoded_bech32.encoding != segwit_addr.Encoding.BECH32:
#         raise ValueError("Bad bech32 encoding: must be using vanilla BECH32")
#     if hrp != 'ln':
#         raise Exception('unexpected hrp: {}'.format(hrp))
#     data_8bits = segwit_addr.convertbits(data_5bits, 5, 8, False)
#     # pad with zeroes
#     COMPRESSED_PUBKEY_LENGTH = 33
#     data_8bits = data_8bits + ((COMPRESSED_PUBKEY_LENGTH - len(data_8bits)) * [0])
#     return bytes(data_8bits)
#
#
# def make_closing_tx(local_funding_pubkey: bytes, remote_funding_pubkey: bytes,
#                     funding_txid: str, funding_pos: int, funding_sat: int,
#                     outputs: List[PartialTxOutput]) -> PartialTransaction:
#     c_input = make_funding_input(local_funding_pubkey, remote_funding_pubkey,
#         funding_pos, funding_txid, funding_sat)
#     c_input.nsequence = 0xFFFF_FFFF
#     tx = PartialTransaction.from_io([c_input], outputs, locktime=0, version=2)
#     return tx
#
#
# def split_host_port(host_port: str) -> Tuple[str, str]: # port returned as string
#     ipv6  = re.compile(r'\[(?P<host>[:0-9a-f]+)\](?P<port>:\d+)?$')
#     other = re.compile(r'(?P<host>[^:]+)(?P<port>:\d+)?$')
#     m = ipv6.match(host_port)
#     if not m:
#         m = other.match(host_port)
#     if not m:
#         raise ConnStringFormatError('Connection strings must be in <node_pubkey>@<host>:<port> format')
#     host = m.group('host')
#     if m.group('port'):
#         port = m.group('port')[1:]
#     else:
#         port = '9735'
#     try:
#         int(port)
#     except ValueError:
#         raise ConnStringFormatError('Port number must be decimal')
#     return host, port
#
#
# def extract_nodeid(connect_contents: str) -> Tuple[bytes, Optional[str]]:
#     """Takes a connection-string-like str, and returns a tuple (node_id, rest),
#     where rest is typically a host (with maybe port). Examples:
#     - extract_nodeid(pubkey@host:port) == (pubkey, host:port)
#     - extract_nodeid(pubkey@host) == (pubkey, host)
#     - extract_nodeid(pubkey) == (pubkey, None)
#     - extract_nodeid(bolt11_invoice) == (pubkey, None)
#     Can raise ConnStringFormatError.
#     """
#     rest = None
#     try:
#         # connection string?
#         nodeid_hex, rest = connect_contents.split("@", 1)
#     except ValueError:
#         try:
#             # invoice?
#             invoice = lndecode(connect_contents)
#             nodeid_bytes = invoice.pubkey.serialize()
#             nodeid_hex = nodeid_bytes.hex()
#         except Exception:
#             # node id as hex?
#             nodeid_hex = connect_contents
#     if rest == '':
#         raise ConnStringFormatError('At least a hostname must be supplied after the at symbol.')
#     try:
#         node_id = bfh(nodeid_hex)
#         if len(node_id) != 33:
#             raise Exception()
#     except Exception:
#         raise ConnStringFormatError('Invalid node ID, must be 33 bytes and hexadecimal')
#     return node_id, rest
#
#
# # key derivation
# # originally based on lnd/keychain/derivation.go
# # notes:
# # - Add a new path for each use case. Do not reuse existing paths.
# #   (to avoid having to carefully consider if reuse would be safe)
# # - Always prefer to use hardened derivation for new paths you add.
# #   (to avoid having to carefully consider if unhardened would be safe)
# class LnKeyFamily(IntEnum):
#     MULTISIG = 0 | BIP32_PRIME
#     REVOCATION_BASE = 1 | BIP32_PRIME
#     HTLC_BASE = 2 | BIP32_PRIME
#     PAYMENT_BASE = 3 | BIP32_PRIME
#     DELAY_BASE = 4 | BIP32_PRIME
#     REVOCATION_ROOT = 5 | BIP32_PRIME
#     NODE_KEY = 6
#     BACKUP_CIPHER = 7 | BIP32_PRIME
#     PAYMENT_SECRET_KEY = 8 | BIP32_PRIME
#     NOSTR_KEY = 9 | BIP32_PRIME
#
#
# def generate_keypair(node: BIP32Node, key_family: LnKeyFamily) -> Keypair:
#     node2 = node.subkey_at_private_derivation([key_family, 0, 0])
#     k = node2.eckey.get_secret_bytes()
#     cK = ecc.ECPrivkey(k).get_public_key_bytes()
#     return Keypair(cK, k)
#
def generate_random_keypair() -> Keypair:
    import secrets
    k = secrets.token_bytes(32)
    cK = ecc.ECPrivkey(k).get_public_key_bytes()
    return Keypair(cK, k)
#
#
# NUM_MAX_HOPS_IN_PAYMENT_PATH = 20
# NUM_MAX_EDGES_IN_PAYMENT_PATH = NUM_MAX_HOPS_IN_PAYMENT_PATH
#
#
#
#
#
# @attr.s(frozen=True)
# class UpdateAddHtlc:
#     amount_msat = attr.ib(type=int, kw_only=True)
#     payment_hash = attr.ib(type=bytes, kw_only=True, converter=hex_to_bytes, repr=lambda val: val.hex())
#     cltv_abs = attr.ib(type=int, kw_only=True)
#     timestamp = attr.ib(type=int, kw_only=True)
#     htlc_id = attr.ib(type=int, kw_only=True, default=None)
#
#     @stored_in('adds', tuple)
#     def from_tuple(amount_msat, payment_hash, cltv_abs, htlc_id, timestamp) -> 'UpdateAddHtlc':
#         return UpdateAddHtlc(
#             amount_msat=amount_msat,
#             payment_hash=payment_hash,
#             cltv_abs=cltv_abs,
#             htlc_id=htlc_id,
#             timestamp=timestamp)
#
#     def to_json(self):
#         return (self.amount_msat, self.payment_hash, self.cltv_abs, self.htlc_id, self.timestamp)
#
#
# class OnionFailureCodeMetaFlag(IntFlag):
#     BADONION = 0x8000
#     PERM     = 0x4000
#     NODE     = 0x2000
#     UPDATE   = 0x1000
#
#
# class PaymentFeeBudget(NamedTuple):
#     fee_msat: int
#
#     # The cltv budget covers the cost of route to get to the destination, but excluding the
#     # cltv-delta the destination wants for itself. (e.g. "min_final_cltv_delta" is excluded)
#     cltv: int  # this is cltv-delta-like, no absolute heights here!
#
#     #num_htlc: int
#
#     @classmethod
#     def default(cls, *, invoice_amount_msat: int, config: 'SimpleConfig') -> 'PaymentFeeBudget':
#         millionths_orig = config.LIGHTNING_PAYMENT_FEE_MAX_MILLIONTHS
#         millionths = min(max(0, millionths_orig), 250_000)  # clamp into [0, 25%]
#         cutoff_orig = config.LIGHTNING_PAYMENT_FEE_CUTOFF_MSAT
#         cutoff = min(max(0, cutoff_orig), 10_000_000)  # clamp into [0, 10k sat]
#         if millionths != millionths_orig:
#             _logger.warning(
#                 f"PaymentFeeBudget. found insane fee millionths in config. "
#                 f"clamped: {millionths_orig}->{millionths}")
#         if cutoff != cutoff_orig:
#             _logger.warning(
#                 f"PaymentFeeBudget. found insane fee cutoff in config. "
#                 f"clamped: {cutoff_orig}->{cutoff}")
#         # for small payments, fees <= constant cutoff are fine
#         # for large payments, the max fee is percentage-based
#         fee_msat = invoice_amount_msat * millionths // 1_000_000
#         fee_msat = max(fee_msat, cutoff)
#         return PaymentFeeBudget(
#             fee_msat=fee_msat,
#             cltv=NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE,
#         )
