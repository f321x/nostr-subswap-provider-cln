import os

import pytest
from unittest.mock import Mock
import time
from plugin_src.plugin.crypto import sha256
from plugin_src.plugin.invoices import (HoldInvoice, Htlc, HtlcState,
                                        InvoiceState, DuplicateInvoiceCreationError, InsufficientFundedInvoiceError)

DEMO_BOLT11=("lnbc15u1p3xnhl2pp5jptserfk3zk4qy42tlucycrfwxhydvlemu9pqr93tuzlv9cc7g3sdqsvfhkcap3xyhx7un8cqzpgxqzjc"
             "sp5f8c52y2stc300gl6s4xswtjpc37hrnnr3c9wvtgjfuvqmpm35evq9qyyssqy4lgd8tj637qcjp05rdpxxykjenthxftej7a2"
             "zzmwrmrl70fyj9hvj0rewhzj7jfyuwkwcg9g2jpwtk3wkjtwnkdks84hsnu8xps5vsq4gj5hs")

@pytest.fixture
def sample_payment_hash():
    preimage = b'test_preimage'
    return sha256(preimage)


@pytest.fixture
def sample_hold_invoice(sample_payment_hash):
    return HoldInvoice(
        payment_hash=sample_payment_hash.hex(),
        bolt11=DEMO_BOLT11,
        amount_msat=1500000,
        expiry=600
    )


@pytest.fixture
def sample_htlc():
    return Htlc(
        state=HtlcState.ACCEPTED,
        short_channel_id="123x456x789",
        channel_id=12345,
        amount_msat=500000,
        created_at=int(time.time()),
        request_callback=Mock()
    )


def test_hold_invoice_creation(sample_hold_invoice):
    """Test basic HoldInvoice creation and attributes"""
    assert isinstance(sample_hold_invoice.payment_hash, bytes)
    assert sample_hold_invoice.bolt11 == DEMO_BOLT11
    assert sample_hold_invoice.amount_msat == 1500000
    assert sample_hold_invoice.expiry == 600
    assert isinstance(sample_hold_invoice.incoming_htlcs, set)
    assert sample_hold_invoice.funding_status == InvoiceState.UNFUNDED
    assert isinstance(sample_hold_invoice.created_at, int)
    assert sample_hold_invoice.associated_invoice is None


def test_hold_invoice_from_dict(sample_payment_hash):
    """Test creation of HoldInvoice from db dict"""
    data = {
        'payment_hash': sample_payment_hash.hex(),
        'bolt11': DEMO_BOLT11,
        'amount_msat': 1500000,
        'expiry': 600,
        'incoming_htlcs': [],
        'funding_status': InvoiceState.SETTLED.value,
        'created_at': int(time.time()),
        'associated_invoice': sample_payment_hash.hex()
    }
    invoice = HoldInvoice(data)
    assert invoice.payment_hash == sample_payment_hash
    assert invoice.bolt11 == data['bolt11']
    assert invoice.amount_msat == data['amount_msat']
    assert invoice.expiry == data['expiry']
    assert invoice.funding_status == InvoiceState.SETTLED
    assert invoice.associated_invoice == sample_payment_hash


def test_attach_prepay_invoice(sample_hold_invoice, sample_payment_hash):
    """Test attaching a prepay invoice"""
    # Attach bytes hash
    sample_hold_invoice.attach_prepay_invoice(sample_payment_hash)
    assert sample_hold_invoice.associated_invoice == sample_payment_hash

    sample_hold_invoice.associated_invoice = None
    sample_hold_invoice.attach_prepay_invoice(sample_payment_hash.hex())
    assert sample_hold_invoice.associated_invoice == sample_payment_hash

    # Test duplicate attachment
    with pytest.raises(DuplicateInvoiceCreationError):
        sample_hold_invoice.attach_prepay_invoice(sha256(b'another_hash'))


def test_get_prepay_invoice(sample_hold_invoice):
    """Test getting prepay invoice"""
    assert sample_hold_invoice.get_prepay_invoice() is None

    prepay_hash = sha256('prepay_hash')
    sample_hold_invoice.attach_prepay_invoice(prepay_hash.hex())
    assert sample_hold_invoice.get_prepay_invoice() == prepay_hash


def test_find_htlc(sample_hold_invoice, sample_htlc):
    """Test finding HTLC in invoice"""
    # Empty set
    assert sample_hold_invoice.find_htlc(sample_htlc) is None

    # Add HTLC and find it
    sample_hold_invoice.incoming_htlcs.add(sample_htlc)
    found_htlc = sample_hold_invoice.find_htlc(sample_htlc)
    assert found_htlc == sample_htlc


def test_is_fully_funded(sample_hold_invoice):
    """Test fully funded check"""
    htlc1 = Htlc(
        state=HtlcState.ACCEPTED,
        short_channel_id="123x456x789",
        channel_id=12345,
        amount_msat=400000,
        created_at=int(time.time()),
        request_callback=Mock(),
    )
    htlc2 = Htlc(
        state=HtlcState.CANCELLED,
        short_channel_id="123x456x791",
        channel_id=12347,
        amount_msat=1100000,
        created_at=int(time.time()),
        request_callback=Mock(),
    )
    htlc3 = Htlc(
        state=HtlcState.SETTLED,
        short_channel_id="123x456x790",
        channel_id=12346,
        amount_msat=1100000,
        created_at=int(time.time()),
        request_callback=None,
    )

    # Not funded
    sample_hold_invoice.incoming_htlcs.add(htlc1)
    sample_hold_invoice.incoming_htlcs.add(htlc2)  # Cancelled HTLC shouldn't count
    assert not sample_hold_invoice.is_fully_funded()

    # Fully funded
    sample_hold_invoice.incoming_htlcs.add(htlc3)
    assert sample_hold_invoice.is_fully_funded()


def test_cancel_all_htlcs(sample_hold_invoice):
    """Test cancelling all HTLCs"""
    htlc1 = Htlc(
        state=HtlcState.ACCEPTED,
        short_channel_id="123x456x789",
        channel_id=12345,
        amount_msat=500000,
        created_at=int(time.time()),
        request_callback=Mock()
    )
    htlc2 = Htlc(
        state=HtlcState.SETTLED,
        short_channel_id="123x456x790",
        channel_id=12346,
        amount_msat=500000,
        created_at=int(time.time()),
        request_callback=None,
    )

    htlc1.fail = Mock()
    htlc2.fail = Mock()

    sample_hold_invoice.incoming_htlcs.add(htlc1)
    sample_hold_invoice.incoming_htlcs.add(htlc2)

    sample_hold_invoice.cancel_all_htlcs()
    assert sample_hold_invoice.funding_status == InvoiceState.FAILED
    htlc1.fail.assert_called_once()
    htlc2.fail.assert_not_called()


def test_cancel_expired_htlcs(sample_hold_invoice):
    """Test cancelling expired HTLCs"""
    current_time = int(time.time())

    # Create HTLCs with different timestamps
    expired_callback = Mock()
    expired_callback.set_result = Mock()
    htlc_expired = Htlc(
        state=HtlcState.ACCEPTED,
        short_channel_id="123x456x789",
        channel_id=12345,
        amount_msat=500000,
        created_at=int(time.time()) - 10000,  # Expired
        request_callback=expired_callback
    )

    valid_callback = Mock()
    valid_callback.set_result = Mock()
    htlc_valid = Htlc(
        state=HtlcState.ACCEPTED,
        short_channel_id="123x456x790",
        channel_id=12346,
        amount_msat=500000,
        created_at=current_time - 60,  # Not expired
        request_callback=valid_callback
    )

    sample_hold_invoice.incoming_htlcs.add(htlc_expired)
    sample_hold_invoice.incoming_htlcs.add(htlc_valid)

    changes = sample_hold_invoice.cancel_expired_htlcs()
    assert changes
    assert htlc_expired.state == HtlcState.CANCELLED
    assert htlc_valid.state == HtlcState.ACCEPTED
    expired_callback.set_result.assert_called_once()
    valid_callback.set_result.assert_not_called()


def test_settle(sample_hold_invoice):
    """Test settling invoice"""
    preimage = os.urandom(32)
    sample_hold_invoice.payment_hash = sha256(preimage)
    htlc = Htlc(
        state=HtlcState.ACCEPTED,
        short_channel_id="123x456x789",
        channel_id=12345,
        amount_msat=1500000,
        created_at=int(time.time()),
        request_callback=Mock()
    )
    htlc.settle = Mock()

    sample_hold_invoice.incoming_htlcs.add(htlc)
    sample_hold_invoice.settle(preimage)

    assert sample_hold_invoice.funding_status == InvoiceState.SETTLED
    htlc.settle.assert_called_once_with(preimage)


def test_settle_insufficient_funds(sample_hold_invoice):
    """Test settling invoice with insufficient funds"""
    sample_preimage = os.urandom(32)
    sample_hold_invoice.payment_hash = sha256(sample_preimage)
    htlc = Htlc(
        state=HtlcState.ACCEPTED,
        short_channel_id="123x456x789",
        channel_id=12345,
        amount_msat=500000,  # Less than invoice amount
        created_at=int(time.time()),
        request_callback=Mock()
    )
    htlc.settle = Mock()

    sample_hold_invoice.incoming_htlcs.add(htlc)
    with pytest.raises(InsufficientFundedInvoiceError):
        sample_hold_invoice.settle(sample_preimage)
    htlc.settle.assert_not_called()


def test_settle_invalid_preimage(sample_hold_invoice):
    """Test settling with invalid preimage"""
    htlc = Htlc(
        state=HtlcState.ACCEPTED,
        short_channel_id="123x456x789",
        channel_id=12345,
        amount_msat=1000000,
        created_at=int(time.time()),
        request_callback=Mock()
    )

    sample_hold_invoice.incoming_htlcs.add(htlc)
    with pytest.raises(AssertionError):
        sample_hold_invoice.settle(b'wrong_preimage')
    with pytest.raises(TypeError):
        sample_hold_invoice.settle(None)
    with pytest.raises(AssertionError):
        sample_hold_invoice.settle(sha256(b'wrong_preimage'))


def test_to_json(sample_hold_invoice, sample_htlc):
    """Test JSON serialization"""
    sample_hold_invoice.incoming_htlcs.add(sample_htlc)
    json_data = sample_hold_invoice.to_json()
    assert isinstance(json_data['payment_hash'], str)
    assert json_data['bolt11'] == sample_hold_invoice.bolt11
    assert json_data['amount_msat'] == sample_hold_invoice.amount_msat
    assert json_data['expiry'] == sample_hold_invoice.expiry
    assert isinstance(json_data['incoming_htlcs'], list)
    assert json_data['incoming_htlcs'][0] == sample_htlc.to_json()
    assert json_data['funding_status'] == sample_hold_invoice.funding_status.value
    assert json_data['created_at'] == sample_hold_invoice.created_at
    assert json_data['associated_invoice'] is None


def test_hold_invoice_with_htlcs_from_json(sample_payment_hash):
    """Test creation of HoldInvoice with HTLCs from JSON"""
    htlc_json = {
        "_type": "Htlc",
        "state": HtlcState.ACCEPTED.value,
        "short_channel_id": "123x456x789",
        "channel_id": 12345,
        "amount_msat": 1000000,
        "created_at": 1731863844
    }

    data = {
        'payment_hash': sample_payment_hash.hex(),
        'bolt11': DEMO_BOLT11,
        'amount_msat': 1000000,
        'expiry': 3600,
        'incoming_htlcs': [htlc_json],
        'funding_status': InvoiceState.UNFUNDED.value,
        'created_at': int(time.time()),
        'associated_invoice': None
    }

    invoice = HoldInvoice(data)
    assert len(invoice.incoming_htlcs) == 1
    htlc = next(iter(invoice.incoming_htlcs))
    assert htlc.short_channel_id == "123x456x789"
    assert htlc.amount_msat == 1000000
