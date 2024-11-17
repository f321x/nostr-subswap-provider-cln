import time

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock
from plugin_src.plugin.invoices import Htlc, HtlcState, InvalidHtlcState


@pytest.fixture
def sample_htlc_dict():
    return {
        "short_channel_id": "810642x2064x3",
        "id": 12345,
        "amount_msat": 1000000
    }


@pytest.fixture
def sample_callback():
    return Mock()


@pytest.fixture
def basic_htlc(sample_callback):
    return Htlc(
        state=HtlcState.ACCEPTED,
        short_channel_id="810642x2064x3",
        channel_id=12345,
        amount_msat=1000000,
        created_at=1731863844,
        request_callback=sample_callback
    )


def test_htlc_creation(basic_htlc):
    """Test basic HTLC creation and attributes"""
    assert basic_htlc.state == HtlcState.ACCEPTED
    assert basic_htlc.short_channel_id == "810642x2064x3"
    assert basic_htlc.channel_id == 12345
    assert basic_htlc.amount_msat == 1000000
    assert isinstance(basic_htlc.created_at, int)
    assert basic_htlc.created_at == 1731863844


def test_htlc_from_dict(sample_htlc_dict, sample_callback):
    """Test creation of HTLC from cln hook dictionary"""
    htlc = Htlc.from_cln_dict(sample_htlc_dict, sample_callback)
    assert htlc.state == HtlcState.ACCEPTED
    assert htlc.short_channel_id == sample_htlc_dict["short_channel_id"]
    assert htlc.channel_id == sample_htlc_dict["id"]
    assert htlc.amount_msat == sample_htlc_dict["amount_msat"]
    assert htlc.request_callback == sample_callback


def test_htlc_to_json(basic_htlc):
    """Test HTLC serialization to JSON"""
    json_data = basic_htlc.to_json()
    assert json_data["_type"] == "Htlc"
    assert json_data["state"] == basic_htlc.state.value
    assert json_data["short_channel_id"] == basic_htlc.short_channel_id
    assert json_data["channel_id"] == basic_htlc.channel_id
    assert json_data["amount_msat"] == basic_htlc.amount_msat
    assert json_data["created_at"] == 1731863844
    assert "request_callback" not in json_data  # Callback will not be serialized


def test_htlc_from_json():
    """Test HTLC deserialization from JSON"""
    json_data = {
        "_type": "Htlc",
        "state": HtlcState.ACCEPTED.value,
        "short_channel_id": "810642x2064x3",
        "channel_id": 12345,
        "amount_msat": 1000000,
        "created_at": 1731863844
    }
    htlc = Htlc.from_json(json_data)
    assert htlc.state == HtlcState.ACCEPTED
    assert htlc.short_channel_id == "810642x2064x3"
    assert htlc.channel_id == 12345
    assert htlc.amount_msat == 1000000
    assert htlc.created_at == 1731863844
    assert htlc.request_callback is None


def test_htlc_from_json_invalid_type():
    """Test HTLC deserialization with invalid type"""
    json_data = {
        "_type": "NotHtlc",
        "state": HtlcState.ACCEPTED.value,
    }
    with pytest.raises(ValueError):
        Htlc.from_json(json_data)


def test_htlc_equality(basic_htlc):
    """Test HTLC equality comparison"""
    other_htlc = Htlc(
        state=HtlcState.SETTLED,  # Different state
        short_channel_id="810642x2064x3",  # Same
        channel_id=12345,  # Same
        amount_msat=1000000,
        created_at=1731863844,
        request_callback=None
    )
    assert basic_htlc == other_htlc  # Should be equal (only compares channel IDs)

    different_htlc = Htlc(
        state=HtlcState.ACCEPTED,
        short_channel_id="810642x2064x4",  # Different
        channel_id=99999,  # Different
        amount_msat=1000000,
        created_at=1731863844,
        request_callback=None
    )
    assert basic_htlc != different_htlc


def test_htlc_hash(basic_htlc):
    """Test HTLC hash function"""
    # Same channel details should produce same hash
    similar_htlc = Htlc(
        state=HtlcState.SETTLED,
        short_channel_id=basic_htlc.short_channel_id,
        channel_id=basic_htlc.channel_id,
        amount_msat=basic_htlc.amount_msat,
        created_at=basic_htlc.created_at,
        request_callback=None
    )
    print(hash(basic_htlc))
    assert hash(basic_htlc) == hash(similar_htlc)


def test_htlc_fail(basic_htlc):
    """Test HTLC failure"""
    mock_callback = Mock()
    mock_callback.set_result = Mock()
    basic_htlc.request_callback = mock_callback

    basic_htlc.fail()
    assert basic_htlc.state == HtlcState.CANCELLED
    mock_callback.set_result.assert_called_once_with(
        {"result": "fail", "failure_message": "400F"}
    )


def test_htlc_fail_invalid_state():
    """Test HTLC failure with invalid state"""
    htlc = Htlc(
        state=HtlcState.SETTLED,
        short_channel_id="123x456x789",
        channel_id=12345,
        amount_msat=1000000,
        created_at=1731863844,
        request_callback=Mock()
    )
    with pytest.raises(InvalidHtlcState):
        htlc.fail()


def test_htlc_fail_timeout(basic_htlc):
    """Test HTLC timeout failure"""
    mock_callback = Mock()
    mock_callback.set_result = Mock()
    basic_htlc.request_callback = mock_callback

    basic_htlc.fail_timeout()
    assert basic_htlc.state == HtlcState.CANCELLED
    mock_callback.set_result.assert_called_once_with(
        {"result": "fail", "failure_message": "0017"}
    )


def test_htlc_settle(basic_htlc):
    """Test HTLC settlement"""
    mock_callback = Mock()
    mock_callback.set_result = Mock()
    basic_htlc.request_callback = mock_callback

    preimage = b'preimage123'
    basic_htlc.settle(preimage)
    assert basic_htlc.state == HtlcState.SETTLED
    mock_callback.set_result.assert_called_once_with(
        {"result": "resolve", "payment_key": preimage.hex()}
    )


def test_htlc_settle_invalid_state():
    """Test HTLC settlement with invalid state"""
    htlc = Htlc(
        state=HtlcState.CANCELLED,
        short_channel_id="123x456x789",
        channel_id=12345,
        amount_msat=1000000,
        created_at=1731863844,
        request_callback=Mock()
    )
    with pytest.raises(InvalidHtlcState):
        htlc.settle(b'preimage123')


def test_add_new_htlc_callback(basic_htlc):
    """Test adding new callback to HTLC"""
    new_callback = Mock()
    basic_htlc.add_new_htlc_callback(new_callback)
    assert basic_htlc.request_callback == new_callback
