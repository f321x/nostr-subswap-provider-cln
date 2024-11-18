# import pytest
# from unittest.mock import Mock, MagicMock
# from plugin_src.plugin.cln_lightning import CLNLightning
# from plugin_src.plugin.invoices import InvoiceState, HoldInvoice
#
#
# @pytest.fixture
# def mock_plugin():
#     plugin = MagicMock()
#     plugin.plugin.rpc = MagicMock()
#     return plugin
#
#
# @pytest.fixture
# def mock_config():
#     config = MagicMock()
#     config.cln_config = {"cltv-final": {"value_int": 10}}
#     config.network = "testnet"
#     return config
#
#
# @pytest.fixture
# def mock_db():
#     db = MagicMock()
#     db.get_dict.side_effect = lambda x: {}
#     return db
#
#
# @pytest.fixture
# def mock_logger():
#     return MagicMock()
#
#
# @pytest.fixture
# def cln_lightning(mock_plugin, mock_config, mock_db, mock_logger):
#     return CLNLightning(
#         plugin_instance=mock_plugin,
#         config=mock_config,
#         db=mock_db,
#         logger=mock_logger
#     )
#
#
# class TestCLNLightning:
#     def test_initialization(self, cln_lightning):
#         """Test proper initialization of CLNLightning class"""
#         assert cln_lightning.MIN_FINAL_CLTV_DELTA_ACCEPTED == 10
#         assert cln_lightning.MIN_FINAL_CLTV_DELTA_FOR_INVOICE == 13
#         assert len(cln_lightning.monitoring_tasks) == 0
#
#     @pytest.mark.asyncio
#     async def test_run(self, cln_lightning):
#         """Test the run method starts monitoring tasks"""
#         await cln_lightning.run()
#         assert len(cln_lightning.monitoring_tasks) == 2
#
#     def test_handle_htlc_with_invalid_payment_secret(self, cln_lightning):
#         """Test HTLC handling with invalid payment secret"""
#         # Setup mock invoice and HTLC
#         mock_invoice = MagicMock()
#         mock_invoice.bolt11 = "lnbc..."
#         mock_htlc = {
#             "payment_hash": "abc123",
#             "amount_msat": 1000,
#             "cltv_expiry_relative": 144,
#             "short_channel_id": "123x456x0",
#             "id": 1
#         }
#         mock_onion = {"payment_secret": "invalid_secret"}
#
#         # Mock RPC decode response
#         cln_lightning._rpc.decodepay.return_value = {
#             "payment_secret": "valid_secret",
#             "min_final_cltv_expiry": 10
#         }
#
#         result = cln_lightning.handle_htlc(mock_invoice, mock_htlc, mock_onion, MagicMock())
#         assert result is True
#         assert mock_invoice.funding_status != InvoiceState.FUNDED
#
#     def test_handle_htlc_with_valid_payment(self, cln_lightning):
#         """Test HTLC handling with valid payment details"""
#         # Setup mock invoice and HTLC
#         mock_invoice = MagicMock()
#         mock_invoice.bolt11 = "lnbc..."
#         mock_invoice.funding_status = InvoiceState.UNFUNDED
#         mock_invoice.is_fully_funded.return_value = True
#
#         mock_htlc = {
#             "payment_hash": "abc123",
#             "amount_msat": 1000,
#             "cltv_expiry_relative": 144,
#             "short_channel_id": "123x456x0",
#             "id": 1
#         }
#         mock_onion = {"payment_secret": "valid_secret"}
#
#         # Mock RPC decode response
#         cln_lightning._rpc.decodepay.return_value = {
#             "payment_secret": "valid_secret",
#             "min_final_cltv_expiry": 10
#         }
#
#         result = cln_lightning.handle_htlc(mock_invoice, mock_htlc, mock_onion, MagicMock())
#         assert result is True
#         assert mock_invoice.funding_status == InvoiceState.FUNDED
#
#     @pytest.mark.asyncio
#     async def test_pay_invoice_success(self, cln_lightning):
#         """Test successful invoice payment"""
#         mock_bolt11 = "lnbc..."
#         cln_lightning._rpc.pay.return_value = {
#             "status": "complete",
#             "payment_preimage": "preimage123"
#         }
#
#         success, result = await cln_lightning.pay_invoice(bolt11=mock_bolt11, attempts=1)
#         assert success is True
#         assert result == "preimage123"
#
#     @pytest.mark.asyncio
#     async def test_pay_invoice_failure(self, cln_lightning):
#         """Test failed invoice payment"""
#         mock_bolt11 = "lnbc..."
#         cln_lightning._rpc.pay.return_value = {
#             "status": "failed",
#             "error": "payment failed"
#         }
#
#         success, result = await cln_lightning.pay_invoice(bolt11=mock_bolt11, attempts=1)
#         assert success is False
#
#     def test_create_payment_info(self, cln_lightning):
#         """Test creation of payment info"""
#         amount_msat = 1000
#         payment_hash = cln_lightning.create_payment_info(amount_msat=amount_msat)
#         assert len(payment_hash) == 32
#
#     def test_b11invoice_from_hash(self, cln_lightning):
#         """Test creation of bolt11 invoice from payment hash"""
#         payment_hash = bytes([0] * 32)
#         amount_msat = 1000
#         expiry = 3600
#
#         cln_lightning._rpc.listinvoices.return_value = {"invoices": []}
#         cln_lightning._rpc.listpeerchannels.return_value = {"channels": []}
#         cln_lightning._rpc.call.return_value = {"bolt11": "lnbc..."}
#
#         invoice = cln_lightning.b11invoice_from_hash(
#             payment_hash=payment_hash,
#             amount_msat=amount_msat,
#             expiry=expiry
#         )
#
#         assert isinstance(invoice, HoldInvoice)
#         assert invoice.payment_hash == payment_hash
#         assert invoice.amount_msat == amount_msat
#
#     def test_bundle_payments(self, cln_lightning):
#         """Test bundling of swap and prepay invoices"""
#         swap_invoice = MagicMock()
#         swap_invoice.payment_hash = bytes([0] * 32)
#         prepay_invoice = MagicMock()
#         prepay_invoice.payment_hash = bytes([1] * 32)
#
#         cln_lightning._hold_invoices = {
#             swap_invoice.payment_hash.hex(): swap_invoice
#         }
#
#         cln_lightning.bundle_payments(
#             swap_invoice=swap_invoice,
#             prepay_invoice=prepay_invoice
#         )
#
#         assert swap_invoice.attach_prepay_invoice.called_with(prepay_invoice.payment_hash)
#
#     def test_num_sats_can_receive(self, cln_lightning):
#         """Test calculation of inbound capacity"""
#         mock_channels = {
#             "channels": [
#                 {
#                     "connected": True,
#                     "amount_msat": 1000000,
#                     "our_amount_msat": 400000
#                 },
#                 {
#                     "connected": True,
#                     "amount_msat": 2000000,
#                     "our_amount_msat": 1000000
#                 }
#             ]
#         }
#         cln_lightning._rpc.listfunds.return_value = mock_channels
#
#         inbound_capacity = cln_lightning.num_sats_can_receive()
#         expected_capacity = int((1600000 / 1000) * 0.9)  # Convert to sats and apply liquidity factor
#         assert inbound_capacity == expected_capacity
