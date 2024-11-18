import pytest
from unittest.mock import AsyncMock, Mock, patch
import time

from bitcoinrpc import BitcoinRPC, RPCError as BitcoinRPCError
from bitcoinrpc._spec import Error as RPCError
from httpx import Timeout as HttpxTimeout

from plugin_src.plugin.chain_monitor import ChainMonitor, ChainMonitorNotConnectedError, ChainMonitorRpcError
from plugin_src.plugin.cln_logger import PluginLogger
from plugin_src.plugin.utils import BitcoinRPCCredentials, TxMinedInfo
from plugin_src.plugin.transaction import Transaction

# Run the test with the following command:
# pytest tests_chain_monitor.py -v

@pytest.fixture(scope="function")
def logger():
    return Mock(spec=PluginLogger)


@pytest.fixture(scope="function")
def bitcoin_rpc():
    return AsyncMock(spec=BitcoinRPC)


@pytest.fixture(scope="function")
def chain_monitor(logger, bitcoin_rpc):
    return ChainMonitor(logger=logger, bcore_rpc=bitcoin_rpc)


@pytest.mark.asyncio
async def test_init_with_credentials():
    """Test initialization with RPC credentials"""
    logger = Mock(spec=PluginLogger)
    credentials = BitcoinRPCCredentials(host="http://localhost",
                                        port=8332,
                                        user="user",
                                        password="password")

    with patch('bitcoinrpc.BitcoinRPC.from_config') as mock_from_config:
        mock_rpc = AsyncMock(spec=BitcoinRPC)
        mock_from_config.return_value = mock_rpc

        monitor = ChainMonitor(logger=logger, bcore_rpc_credentials=credentials)
        assert monitor.bcore == mock_rpc
        mock_from_config.assert_called_once_with(url=credentials.url, auth=credentials.auth)


@pytest.mark.asyncio
async def test_init_no_config():
    """Test initialization with no config or rpc raises exception"""
    logger = Mock(spec=PluginLogger)
    with pytest.raises(Exception, match="ChainMonitor: No Bitcoin Core rpc config found"):
        ChainMonitor(logger=logger)


@pytest.mark.asyncio
async def test_test_connection_success(chain_monitor):
    """Test successful RPC connection"""
    chain_monitor.bcore.getblockchaininfo.return_value = {"blocks": 100}
    await chain_monitor._test_connection()
    chain_monitor.bcore.getblockchaininfo.assert_called_once()


@pytest.mark.asyncio
async def test_test_connection_failure(chain_monitor):
    """Test failed RPC connection"""
    chain_monitor.bcore.getblockchaininfo.side_effect = BitcoinRPCError(id=1,
                                                                        error=RPCError(code=-5, message="Connection failed"))
    with pytest.raises(ChainMonitorNotConnectedError):
        await chain_monitor._test_connection()


@pytest.mark.asyncio
async def test_txindex_enabled_success(chain_monitor):
    """Test successful txindex check"""
    chain_monitor.bcore.acall.return_value = {"txindex": {"synced": True}}
    result = await chain_monitor._txindex_enabled()
    assert result is True
    chain_monitor.bcore.acall.assert_called_once_with(
        method="getindexinfo",
        params=[],
        timeout=HttpxTimeout(5)
    )


@pytest.mark.asyncio
async def test_txindex_disabled(chain_monitor):
    """Test when txindex is disabled"""
    chain_monitor.bcore.acall.return_value = {"txindex": {"synced": False}}
    result = await chain_monitor._txindex_enabled()
    assert result is False

    # Additional test call with return_value = {}
    chain_monitor.bcore.acall.return_value = {}
    result = await chain_monitor._txindex_enabled()
    assert result is False


@pytest.mark.asyncio
async def test_run_success(chain_monitor):
    """Test successful run"""
    chain_monitor.bcore.getblockchaininfo.return_value = {"blocks": 100}
    chain_monitor.bcore.acall.return_value = {"txindex": {"synced": True}}
    await chain_monitor.run()


@pytest.mark.asyncio
async def test_run_no_txindex(chain_monitor):
    """Test run fails when txindex is disabled"""
    chain_monitor.bcore.getblockchaininfo.return_value = {"blocks": 100}
    chain_monitor.bcore.acall.return_value = {"txindex": {"synced": False}}
    with pytest.raises(ChainMonitorRpcError, match="ChainMonitor: txindex is not enabled"):
        await chain_monitor.run()


def test_add_callback(chain_monitor):
    """Test adding callback"""
    mock_callback = Mock()
    address = "tb1qd28npep0s8frcm3y7dxqajkcy2m40eysplyr9v"
    chain_monitor.add_callback(address, mock_callback)
    assert chain_monitor.callbacks[address] == mock_callback


def test_remove_callback(chain_monitor):
    """Test removing callback"""
    mock_callback = Mock()
    address = "bc1qryhgpmfv03qjhhp2dj8nw8g4ewg08jzmgy3cyx"
    chain_monitor.add_callback(address, mock_callback)
    chain_monitor.remove_callback(address)
    assert address not in chain_monitor.callbacks


@pytest.mark.asyncio
async def test_is_up_to_date_success(chain_monitor):
    """Test successful blockchain sync check"""
    current_time = int(time.time())
    chain_monitor.bcore.getblockchaininfo.return_value = {
        "blocks": 100,
        "headers": 100,
        "bestblockhash": "00000000000000000001c3ca0ae9478b0ca2e870daadbc179ce6515a02305448"
    }
    chain_monitor.bcore.getblockheader.return_value = {
        "time": current_time - 1200 # 20 minutes ago
    }
    result = await chain_monitor.is_up_to_date()
    assert result is True


@pytest.mark.asyncio
async def test_is_up_to_date_not_synced(chain_monitor):
    """Test when blockchain is not synced"""
    chain_monitor.bcore.getblockchaininfo.return_value = {
        "blocks": 100,
        "headers": 200,  # more headers than blocks
        "bestblockhash": "00000000000000000001c3ca0ae9478b0ca2e870daadbc179ce6515a02305448"
    }
    result = await chain_monitor.is_up_to_date()
    assert result is False


@pytest.mark.asyncio
async def test_get_tx_height(chain_monitor):
    """Test getting transaction height"""
    mock_tx_data = {
        "confirmations": 10,
        "blockhash": "00000000000000000001c3ca0ae9478b0ca2e870daadbc179ce6515a02305448",
        "blocktime": 1234567890,
        "locktime": 0
    }
    mock_block_header = {
        "height": 100
    }

    chain_monitor.bcore.getrawtransaction.return_value = mock_tx_data
    chain_monitor.bcore.getblockheader.return_value = mock_block_header

    result = await chain_monitor.get_tx_height("50ecbbabead95f720d390337f9b973bc5488178269b6e805714623710f5af81e")
    assert isinstance(result, TxMinedInfo)
    assert result.height == 100
    assert result.conf == 10
    assert result.timestamp == 1234567890


@pytest.mark.asyncio
async def test_get_transaction_success(chain_monitor):
    """Test getting transaction"""
    mock_raw_tx = ("02000000000101076f37740d86b3b9356aef6e3be76c5f73506aba2ad5ef012ab9726c8d"
                   "59b6a90100000000fdffffff0243d7730900000000160014192e80ed2c7c412bdc2a6c8f"
                   "371d15cb90f3c85b354e0c000000000017a91425b62e5c1f915314fc834811e1b2f05ae9"
                   "873366870247304402205e03436af4933e5eeba8ea10cd88b1c9e4c328363aee9ccc4096"
                   "7575c3778e5702204b3238791a0985eb15d2a1454704c97cf70bebe6427496a98a204a82"
                   "6fb2fca2012103b01bd095f648ea829f000207087f16622431077bb5cc0875225ada6013"
                   "75c88500000000")
    chain_monitor.bcore.getrawtransaction.return_value = mock_raw_tx
    reference_tx = Transaction(raw=mock_raw_tx)
    result = await chain_monitor.get_transaction("50ecbbabead95f720d390337f9b973bc5488178269b6e805714623710f5af81e")
    assert result == reference_tx


@pytest.mark.asyncio
async def test_get_transaction_not_found(chain_monitor):
    """Test getting non-existent transaction"""
    # error_response = {"code": -5, "message": "No such mempool or blockchain transaction."}
    chain_monitor.bcore.getrawtransaction.side_effect = BitcoinRPCError(id=1,
                                                                        error=RPCError(code=-5,
                                                                                        message="No such mempool or blockchain transaction."))
    result = await chain_monitor.get_transaction("50ecbbabead95f720d390337f9b973bc5488178269b6e805714623710f5af81e")
    assert result is None
