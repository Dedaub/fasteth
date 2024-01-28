from typing import Any

import httpx
from eth_utils.conversions import to_hex, to_int

from fasteth import models, types

default_block_id: types.ETHBlockIdentifier = "latest"
position_zero: types.Bytes = types.Bytes.validate("0x0")
result_key = "result"
localhost = "http://localhost:8545/"
json_headers = {"Content-Type": "application/json"}


class AsyncJSONRPCCore(httpx.AsyncClient):
    """Asynchronous remote procedure call client."""

    def __init__(
        self,
        rpc_uri: str = localhost,
        http2: bool = False,
        **kwargs,
    ):
        """Initialize JSON RPC.

        :param rpc_uri: RPC URI for ethereum client.
        :param http2: Boolean to use http2 when true.
        """
        super().__init__(http2=http2, **kwargs)
        self.rpc_uri = rpc_uri

    async def rpc(self, rpc_request: models.JSONRPCRequest) -> Any:
        """Return JSONRPCResponse for the JSONRPCRequest, executing a RPC.

        :raises eth_exceptions.JSONRPCError
        :raises httpx.HTTPStatusError
        :raises httpx.StreamError"""
        response = await self.post(
            url=self.rpc_uri,
            headers=json_headers,
            content=rpc_request.model_dump_json(exclude_none=True),
        )
        # We want to raise here http errors.
        response.raise_for_status()
        # Now we get back the JSON and do error handling.
        rpc_response = models.JSONRPCResponse.model_validate_json(response.content)
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

    async def sha3(self, data: types.Bytes) -> types.ETHWord:
        """Returns the Keccak-256 of the given data.

        Consider using eth_utils.sha3 instead to save the round trip.

        :param data: types.Bytes of types.Bytes to Keccak-256 hash.

        :returns
            types.Bytes: Keccak-256 bytes of types.Bytes
        """
        return types.ETHWord.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.sha3[0],
                    id=self.rpc_schema.sha3[1],
                    params=[data],
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
        return types.Uint256.validate(
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
        return types.Uint256.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.protocol_version[0],
                    id=self.rpc_schema.protocol_version[1],
                )
            )
        )

    async def syncing(self) -> models.SyncStatus | bool:
        """Returns an object with sync status data.

        Calls eth_syncing.

        :returns
            models.SyncStatus or False: with sync status data or False when
                                               not syncing.
        """
        # It mystifies me why this can't return a proper JSON boolean.
        result = await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.syncing[0], id=self.rpc_schema.syncing[1]
            )
        )

        if isinstance(result, bool):
            return result
        else:
            return models.SyncStatus.model_validate(result)

    async def coinbase(self) -> types.ETHAddress:
        """Returns the client coinbase address

        Calls eth_coinbase.

        :returns
            str:The current coinbase address.
        :raises
           :exception JSONRPCError: when this method is not supported.
        """
        return types.ETHAddress.validate(
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
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.mining[0], id=self.rpc_schema.mining[1]
            )
        )

    async def hashrate(self) -> int:
        """Returns the number of hashes per second that the node is mining with.

        Calls eth_hashrate.

        :returns:
            int:Number of hashes per second.
        """
        return types.Uint256.validate(
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
        return types.Uint256.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.gas_price[0], id=self.rpc_schema.gas_price[1]
                )
            )
        )

    async def accounts(self) -> list[types.ETHAddress]:
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
        return types.Uint256.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.block_number[0],
                    id=self.rpc_schema.block_number[1],
                )
            )
        )

    async def get_logs(self, logs_request: models.LogsFilter) -> list[models.Log]:
        """Returns an array of all logs matching a given filter object.

        Calls eth_getLogs.

        :param object: a filter object which contains
        the following fields ->
            :param fromBlock: a types.ETHBlockIdentifier to
            specify where to start checking.
            :param toBlock: a types.ETHBlockIdentifier to
            specify where to end checking.
            :param address: The contract address or a list
            of addresses from which logs should originate from.
            :param topics: a list[types.ETHWord] to check event
            topics against.
            :param blockHash: an types.ETHBlockIdentifier of
            the block to check in.

        :returns
            list[models.Log]: A list of logs which sastisfy the filter object.
        """

        logs_request.fromBlock = (
            hex(logs_request.fromBlock)
            if isinstance(logs_request.fromBlock, types.Uint256)
            else logs_request.fromBlock
        )

        logs_request.toBlock = (
            hex(logs_request.toBlock)
            if isinstance(logs_request.toBlock, types.Uint256)
            else logs_request.toBlock
        )

        request = models.JSONRPCRequest(
            method=self.rpc_schema.get_logs[0],
            id=self.rpc_schema.get_logs[1],
            params=[logs_request],
        )

        return [models.Log.model_validate(log) for log in await self.rpc(request)]

    async def get_balance(
        self,
        address: types.ETHAddress,
        block_identifier: types.ETHBlockIdentifier = default_block_id,
    ) -> int:
        """Returns the balance of the given address during the given block block_number.

        Calls eth_getBalance.

        :param address: an ethereum address to get the balance of.
        :param block_identifier: an types.ETHBlockIdentifier of the block
                                 number to check at.

        :returns
            int: The balance in wei during block_number.
        """
        return types.Uint256.validate(
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
        address: types.ETHAddress,
        position: int = 0,
        block_identifier: types.ETHBlockIdentifier = default_block_id,
    ) -> types.Bytes:
        """Returns storage from position at a given address during block_identifier.

        Calls eth_getStorageAt.

        See: https://eth.wiki/json-rpc/API#eth_getstorageat

        There are some usage examples at that link which are useful.

        eth_utils.keccak and eth-hash are useful here as well.

        :param address: types.Address address of the storage.
        :param position: integer as types.Bytes of the position in the storage.
        :param block_identifier: types.ETHBlockIdentifier for the block to
                                 retrieve from.

        :returns types.Bytes: containing the data at the address, position,
                                 block_identifier.
        """
        return types.Bytes.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_storage_at[0],
                    id=self.rpc_schema.get_storage_at[1],
                    params=[
                        address,
                        to_hex(position),
                        block_identifier,
                    ],
                )
            )
        )

    async def get_transaction_count(
        self,
        address: types.ETHAddress,
        block_identifier: types.ETHBlockIdentifier = default_block_id,
    ) -> int:
        """Returns the number of transactions sent from an address.

        Calls eth_getTransactionCount

        :param address: address to get count for.
        :param block_identifier: types.ETHBlockIdentifier to get count at.

        :returns int: The number of transactions sent from address.
        """
        return types.Uint256.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_transaction_count[0],
                    id=self.rpc_schema.get_transaction_count[1],
                    params=[address, block_identifier],
                )
            )
        )

    async def get_block_transaction_count_by_hash(
        self, block_hash: types.ETHWord
    ) -> types.Uint256:
        """Returns the number of txns in a block matching the given block_hash.

        Calls eth_getBlockTransactionCountByHash.

        Can raise an exception converting integer if block_hash is is invalid.

        :param block_hash: types.ETHWord of the block.

        :returns
            int: Transaction count for given block.
        """
        data = await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.get_block_transaction_count_by_hash[0],
                id=self.rpc_schema.get_block_transaction_count_by_hash[1],
                params=[block_hash],
            )
        )

        return types.Uint256.validate(data if data is not None else 0)

    async def get_block_transaction_count_by_number(
        self, block_identifier: types.ETHBlockIdentifier
    ) -> int:
        """Returns the number of txns in a block matching the given block_identifier.

        Calls eth_getBlockTransactionCountByNumber.

        Can raise an exception converting integer if block_identifier is is invalid.

        :param block_identifier: types.ETHBlockIdentifier of the block.

        :returns
            int: Transaction count for given block.
        """
        return types.Uint256.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_block_transaction_count_by_number[0],
                    id=self.rpc_schema.get_block_transaction_count_by_number[1],
                    params=[block_identifier],
                )
            )
        )

    async def get_uncle_count_by_block_hash(self, block_hash: types.ETHWord) -> int:
        """Returns the number of uncles from a block matching the given block_hash.

        Calls eth_getUncleCountByBlockHash.

        Can raise an exception converting integer if block_hash is is invalid.

        :param block_hash: types.ETHAddress hash of the block.

        :returns
            int: number of uncles in this block.
        """
        return to_int(
            hexstr=await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_uncle_count_by_block_hash[0],
                    id=self.rpc_schema.get_uncle_count_by_block_hash[1],
                    params=[block_hash],
                )
            )
        )

    async def get_uncle_count_by_block_number(
        self, block_identifier: types.ETHBlockIdentifier
    ) -> int:
        """Returns the number of uncles block matching the given block_identifier.

        Calls eth_getUncleCountByBlockNumber.

        Can raise an exception converting integer if block_identifier is is invalid.

        :param block_identifier: types.ETHBlockIdentifier of the block.

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
        address: types.ETHAddress,
        block_identifier: types.ETHBlockIdentifier = default_block_id,
    ) -> types.HexBytes:
        """Return code at a given address during specified block.

        :param address: The address to retrieve the code from.
        :param block_identifier: the block during which to get the code from.

        :returns
            types.Bytes: string in hex format containing the code as data.
        """
        return types.HexBytes.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.get_code[0],
                    id=self.rpc_schema.get_code[1],
                    params=[address, block_identifier],
                )
            )
        )

    async def sign(
        self, address: types.ETHAddress, message: types.Bytes
    ) -> types.Bytes:
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
            types.Bytes: signature
        """
        return types.Bytes.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.sign[0],
                    id=self.rpc_schema.sign[1],
                    params=[address, message],
                )
            )
        )

    async def sign_transaction(self, transaction: models.CallParams) -> types.Bytes:
        """Returns a signed transaction object as types.Bytes.

        Signs and returns a transaction that can be submitted to the network at a
        later time using with send_raw_transaction.

        Calls eth_signTransaction

        :param transaction: models.Transaction object to sign.

        :returns
           types.Bytes: The signed transaction object.
        """
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.sign_transaction[0],
                id=self.rpc_schema.sign_transaction[1],
                params=[transaction],
            )
        )

    async def send_transaction(self, transaction: models.CallParams) -> types.Bytes:
        """Creates new message call transaction or a contract creation.

        :param transaction: models.Transaction object to send.

        :returns
           types.Bytes: the transaction hash, or the zero hash if the transaction
                             is not yet available.
        """

        return types.Bytes.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.send_transaction[0],
                    id=self.rpc_schema.send_transaction[1],
                    params=[transaction],
                )
            )
        )

    async def send_raw_transaction(self, data: types.Bytes) -> types.Bytes:
        """Creates new transaction or a contract creation for signed transactions.

        # TODO(Handle reverted execution)

        :param data: The signed transaction data.

        :returns
           types.Bytes: the transaction hash, or the zero hash if the transaction
                             is not yet available.
        """
        return types.Bytes.validate(
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
        transaction: models.CallParams,
        block_identifier: types.ETHBlockIdentifier,
    ) -> types.Bytes:
        """Execute a new message call without creating a new block chain transaction.

        Calls eth_call.

        :param transaction: models.Transaction call object.
        :param block_identifier: block to call the transaction against.

        :returns
           types.data: The return value of executed contract.
        """
        return types.Bytes.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.call[0],
                    id=self.rpc_schema.call[1],
                    params=[transaction, block_identifier],
                )
            )
        )

    async def estimate_gas(
        self,
        transaction: models.Transaction,
        block_identifier: types.ETHBlockIdentifier,
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
        ret: int = types.Uint256.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.estimate_gas[0],
                    id=self.rpc_schema.estimate_gas[1],
                    params=[transaction, block_identifier],
                )
            )
        )
        return ret

    async def get_block_by_hash(
        self,
        block_id: types.ETHWord,
        full: bool = False,
    ) -> models.FullBlock | models.PartialBlock | None:
        """Returns information about a block by hash.

        Calls the eth_getBlockByHash.

        :param block_id: types.ETHWord of a block.
        :param full: If True it returns the full transaction objects, if False
                     only the hashes of the transactions.

        :returns
            Union[models.Block, None]: A block object, or None when no block found.
        """
        data = await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.get_block_by_hash[0],
                id=self.rpc_schema.get_block_by_hash[1],
                params=[block_id, full],
            )
        )

        if data is None:
            return None

        model = models.FullBlock if full else models.PartialBlock
        return model.model_validate(data)

    async def get_block_by_number(
        self, block_id: types.ETHBlockIdentifier, full: bool
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
        data = await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.get_block_by_number[0],
                id=self.rpc_schema.get_block_by_number[1],
                params=[block_id if isinstance(block_id, str) else hex(block_id), full],
            )
        )

        if data is None:
            return None

        model = models.FullBlock if full else models.PartialBlock
        return model.model_validate(data)

    async def get_block_receipts(
        self, block_id: types.ETHBlockIdentifier
    ) -> list[models.TransactionReceipt] | None:
        """Returns receipts for a specific block number.

        Calls the eth_getBlockReceipts

        :param block_id: Integer of a block number, or the string
                          "earliest", "latest" or "pending", as in the
                          default block parameter.
        :returns
            Union[list[models.TransactionReceipt], None]: A list of transaction
                                                          receipts or None, when
                                                          no block was found.
        """

        data = await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.get_block_receipts[0],
                id=self.rpc_schema.get_block_receipts[1],
                params=[block_id],
            )
        )
        return list(map(models.TransactionReceipt.model_validate, data))

    async def get_transaction_by_hash(
        self,
        tx_hash: types.ETHWord,
    ) -> models.Transaction | None:
        """Returns information about a transaction by hash.

        Calls the eth_getTransactionByHash.

        :param tx_hash: types.ETHWord of a transaction.


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
        return models.Transaction.model_validate(data)

    async def get_transaction_receipt(
        self,
        tx_hash: types.ETHWord,
    ) -> models.TransactionReceipt | None:
        """Returns the receipt of a transaction.

        Calls the eth_getTransactionReceipt

        :param tx_hash: types.ETHWord of a transaction.


        :returns
            models.TransactionReceipt: A Receipt object, or None when no tx found.
        """
        data = await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.get_transaction_receipt[0],
                id=self.rpc_schema.get_transaction_receipt[1],
                params=[tx_hash],
            )
        )
        return models.TransactionReceipt.model_validate(data)

    async def submit_hashrate(
        self,
        hashrate: types.Bytes,
        identifier: types.Bytes,
    ) -> bool:
        """Return code at a given address during specified block.

        Calls eth_submitHashrate.

        :param hashrate: A hexadecimal string representation of the hash rate.
        :param identifier: A random hexadecimal ID identifying the client.

        :returns
            bool: True if submitting went through and false otherwise.
        """
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.submit_hashrate[0],
                id=self.rpc_schema.submit_hashrate[1],
                params=[hashrate, identifier],
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
            bool: Returns true if the message was sent, otherwise false.
        """

        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.shh_post[0],
                id=self.rpc_schema.shh_post[1],
                params=[whisper],
            )
        )

    async def shh_new_identity(self) -> types.Bytes:
        """Creates new whisper identity in the client.

        Calls shh_newIdentity.

        :returns
            types.Bytes: The address of the new identity (60 types.Bytes).
        """
        return types.Bytes.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.shh_new_identity[0],
                    id=self.rpc_schema.shh_new_identity[1],
                )
            )
        )

    async def shh_has_identity(self, identifier: types.Bytes) -> bool:
        """Checks if the client hold the private keys for a given identity.

        Calls shh_hasIdentity.

        :params id: The identity address to check.

        :returns
            bool: Returns true if the message was send, otherwise false.
        """
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.shh_has_identity[0],
                id=self.rpc_schema.shh_has_identity[1],
                params=[identifier],
            )
        )

    async def shh_new_group(self) -> types.Bytes:
        """Create a new whisper group (?).

        Calls shh_newGroup.

        :returns
            types.Bytes: The address of the new group (60 types.Bytes).
        """
        return types.Bytes.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.shh_new_group[0],
                    id=self.rpc_schema.shh_new_group[1],
                )
            )
        )

    async def shh_add_to_group(self, identifier: types.Bytes) -> bool:
        """Add an identity to a group (?).

        Calls shh_addToGroup.

        :params id: The identity address to add to a group.

        :returns
            bool: Returns true if the identity was successfully added to the
                  group, otherwise false (?).
        """
        return await self.rpc(
            models.JSONRPCRequest(
                method=self.rpc_schema.shh_add_to_group[0],
                id=self.rpc_schema.shh_add_to_group[1],
                params=[identifier],
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
        return types.Uint256.validate(
            await self.rpc(
                models.JSONRPCRequest(
                    method=self.rpc_schema.shh_new_filter[0],
                    id=self.rpc_schema.shh_new_filter[1],
                    params=[whisper_filter],
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
        return list(map(models.Message.model_validate, result))

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

        if isinstance(result, bool):
            return result

        return list(map(models.Message.model_validate, result))
