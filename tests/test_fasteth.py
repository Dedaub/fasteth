import asyncio
import re

import pytest

import fasteth
import fasteth.exceptions
from fasteth import models, types

# TODO(add more rigorous testing and parametrized testing)
# These are all "golden path" tests, if you will.

test_address = types.ETHAddress.validate("0x36273803306a3C22bc848f8Db761e974697ece0d")
test_any_address = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
storage_address = types.ETHAddress.validate(
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
)

test_data = types.Bytes.validate("0x00")
zero_block = test_data
zero_block_hash = types.ETHWord.validate(zero_block)
whisper_client = "2"

infura_client = r"Geth\/v[0-9]+\.[0-9]+\.[0-9]+.+"
ganache_client = (
    r"Ganache\/v\d+\.\d+\.\d+\/EthereumJS TestRPC\/v\d+\.\d+\.\d+\/ethereum-js"
)
test_block_hash = types.ETHWord.validate(
    "0xba6c9192229ef4fc8615b510abd2c602f3805b1e51ff8892fb0964e1988ba1e2"
)
test_hashrate_rate = types.Bytes.validate(
    "0x0000000000000000000000000000000000000000000000000000000000500000"
)
test_hashrate_id = types.Bytes.validate(
    "0x59daa26581d0acd1fce254fb7e85952f4c09d0915afd33d3886cd914bc7d283c"
)
test_block_num = types.Uint256.validate("0x7c5b7a")
latest = "latest"


def test_version():
    assert fasteth.__version__ == "0.1.0"


@pytest.fixture(scope="module")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture()
def async_rpc():
    """Returns an AsyncEthereumJSONRPC instance."""
    # This fixture is reused for the entire module test run.
    # Temporary Infura ID
    # TODO(delete this infura project later)
    return fasteth.AsyncEthereumJSONRPC()


@pytest.mark.asyncio
async def test_client_version(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the client version."""
    client_version = await async_rpc.client_version()
    assert isinstance(client_version, str)
    assert re.match(infura_client, client_version) or re.match(
        ganache_client, client_version
    )


@pytest.mark.asyncio
async def test_sha3(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting a sha3/Keccak-256 hash."""
    data_to_hash = types.Bytes(b"hello world")
    hashed = types.ETHWord.validate(
        "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
    )
    hashed_ret = await async_rpc.sha3(data_to_hash)
    assert hashed == hashed_ret


@pytest.mark.asyncio
async def test_network_version(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the network version."""
    network_version = await async_rpc.network_version()
    assert (
        network_version == models.Network.Rinkeby
        or network_version == models.Network.Ganache
        or network_version == models.Network.Mainnet
    )


@pytest.mark.asyncio
async def test_network_listening(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the network version."""
    network_listening = await async_rpc.network_listening()
    assert network_listening


@pytest.mark.asyncio
async def test_network_peer_count(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the network version."""
    peer_count = await async_rpc.network_peer_count()
    assert isinstance(peer_count, int)


@pytest.mark.asyncio
async def test_protocol_version(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the network version."""
    protocol_version = await async_rpc.protocol_version()
    assert protocol_version >= 63


@pytest.mark.asyncio
async def test_syncing(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the network sync status."""
    # Our test client should not by in a syncing state.
    sync_status = await async_rpc.syncing()

    assert isinstance(sync_status, bool) and sync_status is False


@pytest.mark.asyncio
async def test_coinbase(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the coinbase address for the eth client"""
    # We expect this to fail, as our test client does not have a coinbase address.
    try:
        await async_rpc.coinbase()
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_mining(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test checking if eth client is mining"""
    # We our test client to not be mining.
    result = await async_rpc.mining()
    # We really only care about the result.
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_hashrate(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting client hashrate."""
    assert (await async_rpc.hashrate()) == 0


@pytest.mark.asyncio
async def test_gas_price(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the gas price in wei."""
    gas_price = await async_rpc.gas_price()
    assert isinstance(gas_price, int)


@pytest.mark.asyncio
async def test_accounts(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the accounts owned by client."""
    accounts = await async_rpc.accounts()
    assert isinstance(accounts, list)


@pytest.mark.asyncio
async def test_block_number(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the network version."""
    block_number = await async_rpc.block_number()
    assert isinstance(block_number, int)


@pytest.mark.asyncio
async def test_get_balance(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting balance of an account."""
    balance = await async_rpc.get_balance(address=test_address)
    assert isinstance(balance, int)


@pytest.mark.asyncio
async def test_get_transaction_count(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting transaction count for a given address."""
    assert isinstance((await async_rpc.get_transaction_count(test_address)), int)


@pytest.mark.asyncio
async def test_get_block_transaction_count_by_hash(
    async_rpc: fasteth.AsyncEthereumJSONRPC,
):
    """Test getting the block transaction count by hash."""
    assert isinstance(
        (await async_rpc.get_block_transaction_count_by_hash(zero_block_hash)),
        types.Uint256,
    )


@pytest.mark.asyncio
async def test_get_block_transaction_count_by_number(
    async_rpc: fasteth.AsyncEthereumJSONRPC,
):
    """Test getting the block transaction count by number."""
    assert isinstance(
        (
            await async_rpc.get_block_transaction_count_by_number(
                block_identifier=types.Uint256.validate(0)
            )
        ),
        int,
    )


@pytest.mark.asyncio
async def test_get_uncle_count_by_block_hash(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the uncle block count by hash."""
    assert isinstance(
        (await async_rpc.get_uncle_count_by_block_hash(zero_block_hash)),
        int,
    )


@pytest.mark.asyncio
async def test_get_uncle_count_by_block_number(
    async_rpc: fasteth.AsyncEthereumJSONRPC,
):
    """Test getting the block uncle count by number."""
    assert isinstance(
        (
            await async_rpc.get_uncle_count_by_block_number(
                block_identifier=test_block_num
            )
        ),
        int,
    )


@pytest.mark.asyncio
async def test_get_code(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting code from a given address at a given block."""
    storage_contents = await async_rpc.get_code(storage_address)
    assert isinstance(storage_contents, types.Bytes)


@pytest.mark.asyncio
async def test_sign(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test signing and returning the signature."""
    # We expect this to fail because it is unsupported on our test endpoint.
    try:
        await async_rpc.sign(address=test_address, message=test_data)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_sign_transaction(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test signing a transaction and returning the signed transaction."""
    transaction = models.CallParams(from_address=storage_address, data=test_data)  # type: ignore
    # We expect this to fail because it is unsupported on our test endpoint.
    try:
        await async_rpc.sign_transaction(transaction=transaction)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_send_transaction(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test signing a transaction and returning the signed transaction."""
    transaction = models.CallParams(from_address=storage_address, data=test_data)  # type: ignore
    # We expect this to fail because it is unsupported on our test endpoint.
    try:
        await async_rpc.send_transaction(transaction=transaction)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_send_raw_transaction(async_rpc: fasteth.AsyncEthereumJSONRPC):
    # TODO(Fix this test to use a real tx data that works on Rinkeby)
    try:
        await async_rpc.send_raw_transaction(
            types.Bytes.validate(
                "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8e"
                "b970870f072445675"
            )
        )
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_call(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test call to a contract function without posting a transaction."""
    transaction = models.CallParams(from_address=storage_address, data=test_data)  # type: ignore
    # TODO(Get working test data in place)
    try:
        await async_rpc.call(transaction=transaction, block_identifier=latest)
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_estimate_gas(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test call to a contract function without posting a transaction."""
    transaction = models.CallParams(from_address=storage_address, data=test_data)  # type: ignore
    # TODO(Get working test data in place)
    try:
        await async_rpc.estimate_gas(
            transaction=transaction, block_identifier="pending"
        )
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_get_block_by_hash(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting a block by number."""
    block = await async_rpc.get_block_by_hash(
        types.ETHWord.validate(
            "0xec1ec1738c4b62b6c519c3e24b3030927317a42b17907dc94d96f947df1d2267"
        ),
        True,
    )
    assert isinstance(block, models.FullBlock)
    assert block.number == 16397796
    assert block.baseFeePerGas == 14879286010


@pytest.mark.asyncio
async def test_get_block_by_number(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting a block by number."""
    block = await async_rpc.get_block_by_number(types.Uint256.validate(0), True)
    assert isinstance(block, models.BaseBlock)


@pytest.mark.asyncio
async def test_submit_hashrate(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test submitting a hashrate."""
    submitted = await async_rpc.submit_hashrate(test_hashrate_rate, test_hashrate_id)
    assert isinstance(submitted, bool)


@pytest.mark.asyncio
async def test_shh_version(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting the client version."""
    try:
        client_version = await async_rpc.shh_version()
        assert isinstance(client_version, str)
        assert client_version == whisper_client
    except fasteth.exceptions.JSONRPCError:
        pass


@pytest.mark.asyncio
async def test_get_transaction_by_hash(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting a tx by hash."""
    tx = await async_rpc.get_transaction_by_hash(
        types.ETHWord.validate(
            "0x270c9f96972fa465d2e2efa1c68ea6117e48b3e5d21ce0dcce2f72bda9f2cbdb"
        )
    )
    assert isinstance(tx, models.Transaction)
    assert tx.from_address == types.ETHAddress.validate(
        "0xd2090025857b9c7b24387741f120538e928a3a59"
    )
    assert tx.to == types.ETHAddress.validate(
        "0x4675c7e5baafbffbca748158becba61ef3b0a263"
    )
    # assert tx.blockHash == "0xec1ec1738c4b62b6c519c3e24b3030927317a42b17907dc94d96f947df1d2267"
    blockByHash = await async_rpc.get_block_by_hash(tx.blockHash, full=False)
    assert blockByHash.number == tx.blockNumber


@pytest.mark.asyncio
async def test_get_transaction_receipt(async_rpc: fasteth.AsyncEthereumJSONRPC):
    """Test getting a tx by hash."""
    tx = await async_rpc.get_transaction_receipt(
        types.ETHWord.validate(
            "0x270c9f96972fa465d2e2efa1c68ea6117e48b3e5d21ce0dcce2f72bda9f2cbdb"
        )
    )
    assert isinstance(tx, models.TransactionReceipt)
    assert tx.from_address == types.ETHAddress.validate(
        "0xd2090025857b9c7b24387741f120538e928a3a59"
    )
    assert tx.to == types.ETHAddress.validate(
        "0x4675c7e5baafbffbca748158becba61ef3b0a263"
    )
    # assert tx.blockHash == "0xec1ec1738c4b62b6c519c3e24b3030927317a42b17907dc94d96f947df1d2267"
    blockByHash = await async_rpc.get_block_by_hash(tx.blockHash, full=False)

    assert blockByHash is not None

    assert blockByHash.number == tx.blockNumber


if __name__ == "__main__":
    """For running directly via CLI."""
    import sys

    import pytest

    pytest.main(sys.argv)
