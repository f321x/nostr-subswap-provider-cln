# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
from enum import IntFlag
import attr
import electrum_ecc as ecc

from .globals import get_plugin_logger


_logger = get_plugin_logger()


# defined in BOLT-03:
HTLC_TIMEOUT_WEIGHT = 663
HTLC_SUCCESS_WEIGHT = 703
COMMITMENT_TX_WEIGHT = 724
HTLC_OUTPUT_WEIGHT = 172

REDEEM_AFTER_DOUBLE_SPENT_DELAY = 30

LN_MAX_FUNDING_SAT_LEGACY = pow(2, 24) - 1
DUST_LIMIT_MAX = 1000


hex_to_bytes = lambda v: v if isinstance(v, bytes) else bytes.fromhex(v) if v is not None else None
bytes_to_hex = lambda v: repr(v.hex()) if v is not None else None
json_to_keypair = lambda v: v if isinstance(v, OnlyPubkeyKeypair) else Keypair(**v) if len(v)==2 else OnlyPubkeyKeypair(**v)


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


    if hasattr(IntFlag, "_numeric_repr_"):  # python 3.11+
        # performance improvement (avoid base2<->base10), see #8403
        _numeric_repr_ = hex

    def __repr__(self):
        # performance improvement (avoid base2<->base10), see #8403
        return f"<{self._name_}: {hex(self._value_)}>"

    def __str__(self):
        # performance improvement (avoid base2<->base10), see #8403
        return hex(self._value_)


def generate_random_keypair() -> Keypair:
    import secrets
    k = secrets.token_bytes(32)
    cK = ecc.ECPrivkey(k).get_public_key_bytes()
    return Keypair(cK, k)
