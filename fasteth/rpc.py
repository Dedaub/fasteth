# 3rd party imports
from typing import Any

# noinspection PyPackageRequirements
import httpx
import orjson
from eth_utils.conversions import to_hex, to_int

from fasteth import models, types, utils

# TODO(Websocket support)
# TODO(IPC Support)
# TODO(Add doc about https://eth.wiki/json-rpc/API#the-default-block-parameter)
# TODO(Consider this: https://github.com/ethereum/snake-charmers-tactical-manual)
# Reminder, use decimal.Decimal for any math involving 2 integers becoming a float.
# That is the python style guide for ethereum projects.
# See https://docs.soliditylang.org/en/latest/abi-spec.html

# pile of "magic" variables to deal with.
# TODO(move these out of the module scope)
default_block_id: types.DefaultBlockIdentifier = "latest"
position_zero: types.Data = utils.to_eth_converters[types.Data]("0x0")
result_key = "result"
localhost = "http://localhost:8545/"
json_headers = {"Content-Type": "application/json"}


class AsyncJSONRPCCore(httpx.AsyncClient):
    """Asynchronous remote procedure call client."""

    def __init__(self, rpc_uri: str = localhost, http2: bool = False):
        """Initialize JSON RPC.

        :param rpc_uri: RPC URI for ethereum client.
        :param http2: Boolean to use http2 when true.
        """
        super().__init__(http2=http2)
        self.rpc_uri = rpc_uri

    async def rpc(self, rpc_request: models.JSONRPCRequest) -> Any:
        """Return JSONRPCResponse for the JSONRPCRequest, executing a RPC.

        :raises eth_exceptions.JSONRPCError
        :raises httpx.HTTPStatusError
        :raises httpx.StreamError"""
        response = await self.post(
            url=self.rpc_uri,
            headers=json_headers,
            content=orjson.dumps(rpc_request.dict()),
        )
        # We want to raise here http errors.
        response.raise_for_status()
        # Now we get back the JSON and do error handling.
        rpc_response = models.JSONRPCResponse.parse_obj(orjson.loads(response.content))
        if rpc_response.error:
            rpc_response.error.raise_for_error()
        return rpc_response.result


class AsyncEthereumJSONRPC(AsyncJSONRPCCore):
    """Presents an asynchronous interface to the ethereum JSON RPC.

    This class aggressively converts the strings returned in result
    bodies into efficient native python data eth_types in cases where a string
    is returned in place of an int, et cētera.

    The API info at https://eth.wiki/json-rpc/API was highly helpful in
    creating this.
    """

    rpc_schema = models.RPCSchema

    async def client_version(self) -> str:
        """Return the current ethereum client version as a string.

        Calls web3_clientVersion

        :returns
            string: The current client version.
        """
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.client_version[0],
                id=self.rpc_schema.client_version[1],
            )
        )

    async def sha3(self, data: types.Data) -> types.Data:
        """Returns the Keccak-256 of the given data.

        Consider using eth_utils.sha3 instead to save the round trip.

        :param data: Bytes of types.Data to Keccak-256 hash.

        :returns
            types.Data: Keccak-256 bytes of types.Data
        """
        return utils.to_py_converters[types.Hash32](
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.sha3[0],
                    id=self.rpc_schema.sha3[1],
                    params=[utils.to_eth_converters[types.Data](data)],
                )
            )
        )

    async def network_version(self) -> models.Network:
        """Returns the current network ID.

        Calls net_version.

        :returns
            Network:Enum populated with network ID.
        """
        # noinspection PyArgumentList
        # PyCharm is incorrect here.
        return models.Network(
            int(
                await self.rpc(
                    models.JSONRPCRequest(
                        method=self.rpc_schema.network_version[0],
                        id=self.rpc_schema.network_version[1],
                    )
                )
            )
        )

    async def network_listening(self) -> bool:
        """Returns true if client is actively listening for network connections.

        Calls net_listening.

        :returns
            bool: True when listening, otherwise False"""
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.network_listening[0],
                id=self.rpc_schema.network_listening[1],
            )
        )

    async def network_peer_count(self) -> int:
        """Returns number of peers currently connected to the client

        Calls net_peerCount.

        :returns
            int: number of connected peers
        """
        return utils.to_py_converters[int](
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.network_peer_count[0],
                    id=self.rpc_schema.network_peer_count[1],
                )
            )
        )

    async def protocol_version(self) -> int:
        """Returns the current ethereum protocol version.

        Calls eth_protocolVersion.

        :returns
            int: The current Ethereum protocol version as an Integer."""
        return utils.to_py_converters[int](
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.protocol_version[0],
                    id=self.rpc_schema.protocol_version[1],
                )
            )
        )

    async def syncing(self) -> models.SyncStatus:
        """Returns an object with sync status data.

        Calls eth_syncing.

        :returns
            models.SyncStatus or False: with sync status data or False when
                                               not syncing.
        """
        # It mystifies me why this can't return a proper JSON boolean.
        result = utils.result_truthiness(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.syncing[0], id=self.rpc_schema.syncing[1]
                )
            )
        )

        if result:
            result["syncing"] = True
            return models.SyncStatus.parse_obj(result)
        else:
            return models.SyncStatus(syncing=False)

    async def coinbase(self) -> types.HexAddress:
        """Returns the client coinbase address

        Calls eth_coinbase.

        :returns
            str:The current coinbase address.
        :raises
           :exception JSONRPCError: when this method is not supported.
        """
        return types.HexAddress(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.coinbase[0], id=self.rpc_schema.coinbase[1]
                )
            )
        )

    async def mining(self) -> bool:
        """Returns True if the client is actively mining new blocks.

        Calls eth_mining.

        :returns
            bool: True if the client is mining, otherwise False
        """
        # Why can this RPC actually return a bool?
        return utils.result_truthiness(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.mining[0], id=self.rpc_schema.mining[1]
                )
            )
        )

    async def hashrate(self) -> int:
        """Returns the number of hashes per second that the node is mining with.

        Calls eth_hashrate.

        :returns:
            int:Number of hashes per second.
        """
        return utils.to_py_converters[int](
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.hashrate[0], id=self.rpc_schema.mining[1]
                )
            )
        )

    async def gas_price(self) -> int:
        """Returns the current gas price as an integer in wei.

        Calls eth_gasPrice.

        :returns
            int:integer of the current gas price in wei.
        """
        return utils.to_py_converters[int](
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.gas_price[0], id=self.rpc_schema.gas_price[1]
                )
            )
        )

    async def accounts(self) -> list[types.HexAddress]:
        """Returns a list of addresses owned by the client.

        Calls eth_accounts.

        :returns
            list: A list of types.Address owned by the client.
        """
        result = await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.accounts[0], id=self.rpc_schema.accounts[1]
            )
        )

        return result or []

    async def block_number(self) -> int:
        """Returns the number of most recent block.

        Calls eth_blockNumber.

        :returns
            types.BlockNumber: The current block number a client is on as an int.
        """
        return utils.to_py_converters[int](
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.block_number[0],
                    id=self.rpc_schema.block_number[1],
                )
            )
        )

    async def get_balance(
        self,
        address: types.HexAddress,
        block_identifier: types.DefaultBlockIdentifier = default_block_id,
    ) -> int:
        """Returns the balance of the given address during the given block block_number.

        Calls eth_getBalance.

        :param address: an ethereum address to get the balance of.
        :param block_identifier: an types.DefaultBlockIdentifier of the block
                                 number to check at.

        :returns
            int: The balance in wei during block_number.
        """
        return utils.to_py_converters[int](
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_balance[0],
                    id=self.rpc_schema.get_balance[1],
                    params=[address, block_identifier],
                )
            )
        )

    async def get_storage_at(
        self,
        address: types.HexAddress,
        position: int = 0,
        block_identifier: types.DefaultBlockIdentifier = default_block_id,
    ) -> types.Data:
        """Returns storage from position at a given address during block_identifier.

        Calls eth_getStorageAt.

        See: https://eth.wiki/json-rpc/API#eth_getstorageat

        There are some usage examples at that link which are useful.

        eth_utils.keccak and eth-hash are useful here as well.

        :param address: types.Address address of the storage.
        :param position: integer as types.Data of the position in the storage.
        :param block_identifier: types.DefaultBlockIdentifier for the block to
                                 retrieve from.

        :returns types.Data: containing the data at the address, position,
                                 block_identifier.
        """
        return utils.to_py_converters[types.Data](
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_storage_at[0],
                    id=self.rpc_schema.get_storage_at[1],
                    params=[
                        address,
                        utils.to_eth_converters[int](position),
                        block_identifier,
                    ],
                )
            )
        )

    async def get_transaction_count(
        self,
        address: types.HexAddress,
        block_identifier: types.DefaultBlockIdentifier = default_block_id,
    ) -> int:
        """Returns the number of transactions sent from an address.

        Calls eth_getTransactionCount

        :param address: address to get count for.
        :param block_identifier: types.DefaultBlockIdentifier to get count at.

        :returns int: The number of transactions sent from address.
        """
        return utils.to_py_converters[int](
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_transaction_count[0],
                    id=self.rpc_schema.get_transaction_count[1],
                    params=[address, block_identifier],
                )
            )
        )

    # TODO(conversion from block number to hash)
    async def get_block_transaction_count_by_hash(
        self, block_hash: types.Hash32
    ) -> int:
        """Returns the number of txns in a block matching the given block_hash.

        Calls eth_getBlockTransactionCountByHash.

        Can raise an exception converting integer if block_hash is is invalid.

        :param block_hash: types.Hash32 of the block.

        :returns
            int: Transaction count for given block.
        """
        return utils.to_py_converters[int](
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_block_transaction_count_by_hash[0],
                    id=self.rpc_schema.get_block_transaction_count_by_hash[1],
                    params=[utils.to_eth_converters[types.Hash32](block_hash)],
                )
            )
        )

    async def get_block_transaction_count_by_number(
        self, block_identifier: types.DefaultBlockIdentifier
    ) -> int:
        """Returns the number of txns in a block matching the given block_identifier.

        Calls eth_getBlockTransactionCountByNumber.

        Can raise an exception converting integer if block_identifier is is invalid.

        :param block_identifier: types.DefaultBlockIdentifier of the block.

        :returns
            int: Transaction count for given block.
        """
        return utils.to_py_converters[int](
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_block_transaction_count_by_number[0],
                    id=self.rpc_schema.get_block_transaction_count_by_number[1],
                    params=[block_identifier],
                )
            )
        )

    async def get_uncle_count_by_block_hash(self, block_hash: types.Hash32) -> int:
        """Returns the number of uncles from a block matching the given block_hash.

        Calls eth_getUncleCountByBlockHash.

        Can raise an exception converting integer if block_hash is is invalid.

        :param block_hash: types.HexAddress hash of the block.

        :returns
            int: number of uncles in this block.
        """
        return to_int(
            hexstr=await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_uncle_count_by_block_hash[0],
                    id=self.rpc_schema.get_uncle_count_by_block_hash[1],
                    params=[utils.to_eth_converters[types.Hash32](block_hash)],
                )
            )
        )

    async def get_uncle_count_by_block_number(
        self, block_identifier: types.DefaultBlockIdentifier
    ) -> int:
        """Returns the number of uncles block matching the given block_identifier.

        Calls eth_getUncleCountByBlockNumber.

        Can raise an exception converting integer if block_identifier is is invalid.

        :param block_identifier: types.DefaultBlockIdentifier of the block.

        :returns
            int: number of uncles in this block.
        """
        return to_int(
            hexstr=await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_uncle_count_by_block_number[0],
                    id=self.rpc_schema.get_uncle_count_by_block_number[1],
                    params=[block_identifier],
                )
            )
        )

    async def get_code(
        self,
        address: types.HexAddress,
        block_identifier: types.DefaultBlockIdentifier = default_block_id,
    ) -> types.Data:
        """Return code at a given address during specified block.

        :param address: The address to retrieve the code from.
        :param block_identifier: the block during which to get the code from.

        :returns
            types.HexStr: string in hex format containing the code as data.
        """
        return types.Data(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_code[0],
                    id=self.rpc_schema.get_code[1],
                    params=[address, block_identifier],
                )
            )
        )

    async def sign(
        self, address: types.HexAddress, message: types.HexStr
    ) -> types.Data:
        """Returns an signed message.

        sign(keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)))

        By adding a prefix to the message makes the calculated signature recognizable
        as an Ethereum specific signature. This prevents misuse where a malicious
        DApp can sign arbitrary data (e.g. transaction) and use the signature to
        impersonate the victim.

        Note the address to sign with must be unlocked.

        Calls eth_sign.

        TODO(Add tests for this function)

        :param address: address to sign with.
        :param message: hex string of n bytes, message to sign.

        :returns
            types.Data: signature
        """
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.sign[0],
                id=self.rpc_schema.sign[1],
                params=[address, message],
            )
        )

    async def sign_transaction(self, transaction: models.Transaction) -> types.HexStr:
        """Returns a signed transaction object as types.HexStr.

        Signs and returns a transaction that can be submitted to the network at a
        later time using with send_raw_transaction.

        Calls eth_signTransaction

        :param transaction: models.Transaction object to sign.

        :returns
           types.HexStr: The signed transaction object.
        """
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.sign_transaction[0],
                id=self.rpc_schema.sign_transaction[1],
                params=[transaction.dict()],
            )
        )

    async def send_transaction(self, transaction: models.Transaction) -> types.HexStr:
        """Creates new message call transaction or a contract creation.

        :param transaction: models.Transaction object to send.

        :returns
           types.HexStr: the transaction hash, or the zero hash if the transaction
                             is not yet available.
        """

        return types.HexStr(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.send_transaction[0],
                    id=self.rpc_schema.send_transaction[1],
                    params=[transaction.dict()],
                )
            )
        )

    async def send_raw_transaction(self, data: types.HexStr) -> types.HexStr:
        """Creates new transaction or a contract creation for signed transactions.

        # TODO(Handle reverted execution)

        :param data: The signed transaction data.

        :returns
           types.HexStr: the transaction hash, or the zero hash if the transaction
                             is not yet available.
        """
        return types.HexStr(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.send_raw_transaction[0],
                    id=self.rpc_schema.send_raw_transaction[1],
                    params=[data],
                )
            )
        )

    async def call(
        self,
        transaction: models.Transaction,
        block_identifier: types.DefaultBlockIdentifier,
    ) -> types.HexStr:
        """Execute a new message call without creating a new block chain transaction.

        Calls eth_call.

        :param transaction: models.Transaction call object.
        :param block_identifier: block to call the transaction against.

        :returns
           types.data: The return value of executed contract.
        """
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.call[0],
                id=self.rpc_schema.call[1],
                params=[transaction.dict(), block_identifier],
            )
        )

    async def estimate_gas(
        self,
        transaction: models.Transaction,
        block_identifier: types.DefaultBlockIdentifier,
    ) -> int:
        """Returns an estimate of how much gas is necessary to complete the transaction.

        Generates and returns an estimate of how much gas is necessary to allow the
        transaction to complete. The transaction will not be added to the blockchain.
        Note that the estimate may be significantly more than the amount of gas
        actually used by the transaction, for a variety of reasons including EVM
        mechanics and node performance.

        Calls eth_estimateGas.

        :param transaction: models.Transaction call object.
        :param block_identifier: block to call the transaction against.

        :returns
           int: The amount of gas used.
        """
        ret: int = utils.to_py_converters[int](
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.estimate_gas[0],
                    id=self.rpc_schema.estimate_gas[1],
                    params=[transaction.dict(), block_identifier],
                )
            )
        )
        return ret

    async def get_block_by_hash(
        self,
        block_id: types.Hash32,
        full: bool = False,
    ) -> models.FullBlock | models.PartialBlock | None:
        """Returns information about a block by hash.

        Calls the eth_getBlockByHash.

        :param block_id: types.Hash32 of a block.
        :param full: If True it returns the full transaction objects, if False
                     only the hashes of the transactions.

        :returns
            Union[models.Block, None]: A block object, or None when no block found.
        """
        data = await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.get_block_by_hash[0],
                id=self.rpc_schema.get_block_by_hash[1],
                params=[utils.to_eth_converters[types.Hash32](block_id), full],
            )
        )
        return (
            models.FullBlock.parse_obj(data)
            if full
            else models.PartialBlock.parse_obj(data)
        )

    async def get_block_by_number(
        self, block_id: types.DefaultBlockIdentifier, full: bool
    ) -> models.FullBlock | models.PartialBlock | None:

        """Returns information about a block by block number.

        Calls the eth_getBlockByNumber.

        :param block_id: Integer of a block number, or the string
                          "earliest", "latest" or "pending", as in the
                          default block parameter.
        :param full: If true it returns the full transaction objects, if false
                     only the hashes of the transactions.

        :returns
            Union[models.Block, None]: A block object, or None when no block was
                                         found.
        """
        if block_id not in ["pending", "latest", "earliest"]:
            block_id = utils.to_eth_converters[int](block_id)

        data = await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.get_block_by_number[0],
                id=self.rpc_schema.get_block_by_number[1],
                params=[block_id, full],
            )
        )

        return (
            models.FullBlock.parse_obj(data)
            if full
            else models.PartialBlock.parse_obj(data)
        )

    async def get_transaction_by_hash(
        self,
        tx_hash: types.Hash32,
    ) -> models.Transaction | None:
        """Returns information about a transaction by hash.

        Calls the eth_getTransactionByHash.

        :param tx_hash: types.Hash32 of a transaction.


        :returns
            models.Transaction: A Transaction object, or None when no tx found.
        """
        data = await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.get_transaction_by_hash[0],
                id=self.rpc_schema.get_transaction_by_hash[1],
                params=[tx_hash],
            )
        )
        return models.Transaction.parse_obj(data)

    async def submit_hashrate(
        self,
        hashrate: types.HexStr,
        identifier: types.HexStr,
    ) -> bool:
        """Return code at a given address during specified block.

        Calls eth_submitHashrate.

        :param hashrate: A hexadecimal string representation of the hash rate.
        :param identifier: A random hexadecimal ID identifying the client.

        :returns
            bool: True if submitting went through and false otherwise.
        """
        return utils.result_truthiness(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.submit_hashrate[0],
                    id=self.rpc_schema.submit_hashrate[1],
                    params=[hashrate, identifier],
                )
            )
        )

    async def shh_version(self) -> str:
        """Returns the current whisper protocol version.

        Calls shh_version.

        :returns
            str: The current whisper protocol version.
        """
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.shh_version[0], id=self.rpc_schema.shh_version[1]
            )
        )

    async def shh_post(self, whisper: models.Message) -> bool:
        """Sends a whisper message.

        Calls shh_post.

        :param whisper: The whisper post object.

        :returns
            bool: Returns true if the message was send, otherwise false.
        """

        print(
            x := await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.shh_post[0],
                    id=self.rpc_schema.shh_post[1],
                    params=[whisper.dict()],
                )
            )
        )
        print(type(x))
        return x

    async def shh_new_identity(self) -> types.Data:
        """Creates new whisper identity in the client.

        Calls shh_newIdentity.

        :returns
            types.Data: The address of the new identity (60 Bytes).
        """
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.shh_new_identity[0],
                id=self.rpc_schema.shh_new_identity[1],
            )
        )

    async def shh_has_identity(self, identifier: types.Data) -> bool:
        """Checks if the client hold the private keys for a given identity.

        Calls shh_hasIdentity.

        :params id: The identity address to check.

        :returns
            bool: Returns true if the message was send, otherwise false.
        """
        return utils.result_truthiness(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.shh_has_identity[0],
                    id=self.rpc_schema.shh_has_identity[1],
                    params=[identifier],
                )
            )
        )

    async def shh_new_group(self) -> types.Data:
        """Create a new whisper group (?).

        Calls shh_newGroup.

        :returns
            types.Data: The address of the new group (60 Bytes).
        """
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.shh_new_group[0],
                id=self.rpc_schema.shh_new_group[1],
            )
        )

    async def shh_add_to_group(self, identifier: types.Data) -> bool:
        """Add an identity to a group (?).

        Calls shh_addToGroup.

        :params id: The identity address to add to a group.

        :returns
            bool: Returns true if the identity was successfully added to the
                  group, otherwise false (?).
        """
        return utils.result_truthiness(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.shh_add_to_group[0],
                    id=self.rpc_schema.shh_add_to_group[1],
                    params=[identifier],
                )
            )
        )

    async def shh_new_filter(self, whisper_filter: models.WhisperFilter) -> int:
        """Creates filter to notify, when client receives whisper message
        matching the filter options.

        Calls shh_newFilter.

        :params filter: The filter options.

        :returns
            int: The newly created filter.
        """
        return to_int(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.shh_new_filter[0],
                    id=self.rpc_schema.shh_new_filter[1],
                    params=[whisper_filter.dict()],
                )
            )
        )

    async def shh_uninstall_filter(self, identifier: int) -> bool:
        """Uninstalls a filter with given id. Should always be called when
        watch is no longer needed. Additionally, filters timeout when they
        are not requested with shh_getFilterChanges for a period of time.

        Calls shh_uninstallFilter.

        :params id: The filter id.

        :returns
            bool: True if the filter was successfully uninstalled,
                  otherwise false.
        """
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.shh_uninstall_filter[0],
                id=self.rpc_schema.shh_uninstall_filter[1],
                params=[to_hex(identifier)],
            )
        )

    async def get_shh_filter_changes(self, identifier: int) -> list[models.Message]:
        """Polling method for whisper filters. Returns new messages since the
        last call of this method.

        Note: Calling the shh_getMessages method, will reset the buffer for
        this method, so that you won’t receive duplicate messages.

        Calls shh_getFilterChanges.

        :param identifier: The filter id.

        :returns
            List[models.Messages]: Array of messages received since last poll.
        """
        result = await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.get_shh_filter_changes[0],
                id=self.rpc_schema.get_shh_filter_changes[1],
                params=[to_hex(identifier)],
            )
        )

        return models.iterate_list(models.Message, result)

    async def get_shh_messages(self, identifier: int) -> list[models.Message] | bool:
        """Get all messages matching a filter. Unlike shh_getFilterChanges
        this returns all messages.

        Calls shh_getMessages.

        :param identifier: The filter id.

        :returns
            List[models.Messages]: Array of messages received.
            bool: False if no messages.
        """
        result = await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.get_shh_messages[0],
                id=self.rpc_schema.get_shh_messages[1],
                params=[to_hex(identifier)],
            )
        )

        truthiness = utils.result_truthiness(result)
        if isinstance(truthiness, bool):
            return truthiness

        return models.iterate_list(models.Message, result)
