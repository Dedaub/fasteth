"""Dataclasses for fasteth data types."""
from enum import Enum
from typing import Any, ClassVar, TypeVar, cast

import orjson
from pydantic import BaseModel, Field

from fasteth import exceptions as eth_exp
from fasteth.types import (
    Bytes,
    ETHAddress,
    ETHBlockIdentifier,
    ETHDatetime,
    ETHWord,
    Uint256,
)


class Network(Uint256, Enum):
    """An enum representing the ethereum network id."""

    Mainnet = 1
    Morden = 2
    Ropsten = 3
    Rinkeby = 4
    Kovan = 42
    Ganache = 1337


class RPCSchema(tuple, Enum):
    """An enum representing method and id mappings."""

    client_version = ("web3_clientVersion", 67)
    sha3 = ("web3_sha3", 64)
    network_version = ("net_version", 67)
    network_listening = ("net_listening", 67)
    network_peer_count = ("net_peerCount", 74)
    protocol_version = ("eth_protocolVersion", 67)
    syncing = ("eth_syncing", 1)
    coinbase = ("eth_coinbase", 64)
    mining = ("eth_mining", 71)
    hashrate = ("eth_hashrate", 71)
    gas_price = ("eth_gasPrice", 73)
    accounts = ("eth_accounts", 1)
    block_number = ("eth_blockNumber", 83)
    get_balance = ("eth_getBalance", 1)
    get_storage_at = ("eth_getStorageAt", 1)
    get_transaction_count = ("eth_getTransactionCount", 1)
    get_block_by_number = ("eth_getBlockByNumber", 1)
    get_block_by_hash = ("eth_getBlockByHash", 1)
    get_block_receipts = ("eth_getBlockReceipts", 1)
    get_block_transaction_count_by_hash = ("eth_getBlockTransactionCountByHash", 1)
    get_block_transaction_count_by_number = ("eth_getBlockTransactionCountByNumber", 1)
    get_transaction_by_hash = ("eth_getTransactionByHash", 1)
    get_transaction_receipt = ("eth_getTransactionReceipt", 1)
    get_logs = ("eth_getLogs", 1)
    get_uncle_count_by_block_hash = ("eth_getUncleCountByBlockHash", 1)
    get_uncle_count_by_block_number = ("eth_getUncleCountByBlockNumber", 1)
    get_shh_messages = ("shh_getMessages", 73)
    get_shh_filter_changes = ("shh_getFilterChanges", 73)
    get_code = ("eth_getCode", 1)
    submit_hashrate = ("eth_submitHashrate", 73)
    sign = ("eth_sign", 1)
    sign_transaction = ("eth_signTransaction", 1)
    send_transaction = ("eth_sendTransaction", 1)
    send_raw_transaction = ("eth_sendRawTransaction", 1337)
    call = ("eth_call", 1)
    estimate_gas = ("eth_estimateGas", 1)
    shh_version = ("shh_version", 73)
    shh_post = ("shh_post", 73)
    shh_new_identity = ("shh_newIdentity", 73)
    shh_has_identity = ("shh_hasIdentity", 73)
    shh_new_group = ("shh_newGroup", 73)
    shh_add_to_group = ("shh_addToGroup", 73)
    shh_new_filter = ("shh_newFilter", 73)
    shh_uninstall_filter = ("shh_uninstallFilter", 73)


def orjson_dumps(v, *, default):
    # orjson.dumps returns bytes, to match standard json.dumps we need to decode
    return orjson.dumps(v, default=default).decode()


class AutoEthable(BaseModel):
    class Config:
        # https://docs.pydantic.dev/latest/usage/exporting_models/#custom-json-deserialisation
        # NOTE: that orjson takes care of datetime encoding natively,
        # making it faster than json.dumps but meaning you cannot
        # always customise the encoding using Config.json_encoders.
        #
        # Idk if this is still the case with the ETHDatetime

        json_loads = orjson.loads
        json_dumps = orjson_dumps
        json_encoders = {bytes: lambda x: f"0x{x.hex()}"}


# noinspection PyUnresolvedReferences
class JSONRPCRequest(BaseModel):
    """Model for JSON RPC Request.

    Attributes:
        jsonrpc: A String specifying the version of the JSON-RPC protocol.
                 MUST be exactly "2.0".
        method: A String containing the name of the method to be invoked. Method names
                that begin with the word rpc followed by a period character
                (U+002E or ASCII 46) are reserved for rpc-Uint256ernal methods and
                extensions and MUST NOT be used for anything else.
        params: A Structured value that holds the parameter values to be used during
                the invocation of the method. This member MAY be omitted.
        id: An identifier established by the Client that MUST contain a String, Number,
            or None value if included. If it is not included it is assumed to be a
            notification. The value SHOULD normally not be None and Numbers
            SHOULD NOT contain fractional parts.

    The Server MUST reply with the same value in the Response object if included.
    This member is used to correlate the context between the two objects.

    The use of None as a value for the id member in a Request object is discouraged,
    because this specification uses a value of None for Responses with an unknown id.
    Also, because JSON-RPC 1.0 uses an id value of Null for Notifications this could
    cause confusion in handling.

    Fractional parts may be problematic, since many decimal fractions cannot be
    represented exactly as binary fractions.
    """

    jsonrpc: str = "2.0"
    method: str
    params: list = Field(default_factory=list)
    id: Uint256

    class Config:
        json_encoders = {
            bytes: lambda x: f"0x{x.hex()}",
            Uint256: hex,
        }


class EthereumErrorData(BaseModel):
    # TODO: Break out handling logic here
    code: Uint256
    message: str


# noinspection PyUnresolvedReferences
class JSONRPCErrorData(BaseModel):
    """RPC Call Error Model.

    Attributes:
        code: A Number that indicates the error type that occurred.
              This MUST be an Uint256eger.
        message: A String providing a short description of the error.
                 The message SHOULD be limited to a concise single sentence.
        data: A Primitive or Structured value that contains additional information
              about the error. This may be omitted. The value of this member is
              defined by the Server (e.g. detailed error information, nested
              errors etc.).

    The error codes from and including -32768 to -32000 are reserved for
    pre-defined errors. Any code within this range, but not defined explicitly
    below is reserved for future use. The error codes are nearly the same as those
    suggested for XML-RPC at the following url:
    http://xmlrpc-epi.sourceforge.net/specs/rfc.fault_codes.php

    code 	message 	        meaning
    -32700 	Parse error 	    Invalid JSON was received by the server.
                                An error occurred on the server while parsing
                                the JSON text.
    -32600 	Invalid Request 	The JSON sent is not a valid Request object.
    -32601 	Method not found 	The method does not exist / is not available.
    -32602 	Invalid params 	    Invalid method parameter(s).
    -32603 	Internal error 	    Internal JSON-RPC error.
    -32000
    to
    -32099 	Server error 	    Reserved for implementation-defined server-errors.

    The remainder of the space is available for application defined errors.
    """

    code: Uint256
    message: str
    data: dict | list | list[EthereumErrorData] | Bytes | None
    _exp: ClassVar = {
        -32700: eth_exp.ParseError,
        -32600: eth_exp.InvalidRequest,
        -32601: eth_exp.MethodNotFound,
        -32602: eth_exp.InvalidParams,
        -32603: eth_exp.InternalError,
        1: eth_exp.UnauthorizedError,
        2: eth_exp.ActionNotAllowed,
    }
    _eth_error: ClassVar = {
        100: eth_exp.NotFound,
        101: eth_exp.RequiresEther,
        102: eth_exp.GasTooLow,
        103: eth_exp.GasLimitExceeded,
        104: eth_exp.Rejected,
        105: eth_exp.EtherTooLow,
    }

    def raise_for_error(self):
        if self.code in self._exp:
            if self.code == 3:
                # TODO: Consider raising multiple exceptions here for each error in the list of errors
                for elem in cast(list[EthereumErrorData], self.data):
                    raise self._eth_error[elem.code](elem.message)
            else:
                raise self._exp[self.code](self.message)
        elif self.code in range(-32099, -32000):
            raise eth_exp.ServerError
        else:
            # Raise the generic error.
            raise eth_exp.JSONRPCError


T = TypeVar("T")


class JSONRPCResponse(BaseModel):
    """Model for JSON RPC response.

    Attributes:
        id:  This member is REQUIRED. It MUST be the same as the value of the id
             member in the JSONRPCRequest Object. If there was an error in detecting
             the id in the Request object (e.g. Parse error/Invalid Request), it MUST
             be None.
        jsonrpc: A String specifying the version of the JSON-RPC protocol.
                 MUST be exactly "2.0".
        result: This member is REQUIRED on success. This member MUST NOT exist if
                there was an error invoking the method. The value of this member is
                determined by the method invoked on the Server.
        error: This member is REQUIRED on error. This member MUST NOT exist if
               there was no error triggered during invocation. The value for this
               member MUST be an Object.
        # TODO(Add result and error types according to json rpc spec)
        # https://www.jsonrpc.org/specification
    """

    id: Uint256 | None = None
    jsonrpc: str = "2.0"
    error: JSONRPCErrorData | None = None
    result: dict | list | bool | Any | None = None


class SyncStatus(AutoEthable):
    startingBlock: Uint256
    currentBlock: Uint256
    highestBlock: Uint256


class CallParams(AutoEthable):
    from_address: ETHAddress | None = Field(None, alias="from")
    to: ETHAddress | None = None
    gas: Uint256 | None = None
    gasPrice: Uint256 | None = None
    value: Uint256 | None = None
    data: Bytes | None = None
    blockNumber: ETHBlockIdentifier | None = None


class Transaction(CallParams):
    maxFeePerGas: Uint256 | None = None
    maxPriorityFeePerGas: Uint256 | None = None
    nonce: Uint256
    hash: ETHWord
    input: Bytes
    transactionIndex: Uint256
    blockHash: ETHWord
    type: Uint256
    v: Uint256
    r: ETHWord
    s: ETHWord


class Log(AutoEthable):
    address: ETHAddress
    topics: list[ETHWord]
    data: Bytes
    blockNumber: Uint256
    transactionHash: ETHWord
    transactionIndex: Uint256
    blockHash: ETHWord
    logIndex: Uint256
    removed: bool


class LogsFilter(BaseModel):
    fromBlock: ETHBlockIdentifier | None = None
    toBlock: ETHBlockIdentifier | None = None
    address: ETHAddress | list[ETHAddress]
    topics: list[ETHWord] | None = None
    blockHash: ETHWord | None = None


class TransactionReceipt(AutoEthable):
    blockHash: ETHWord
    blockNumber: Uint256
    contractAddress: ETHAddress | None
    cumulativeGasUsed: Uint256
    effectiveGasPrice: Uint256
    from_address: ETHAddress = Field(..., alias="from")
    gasUsed: Uint256
    logs: list[Log]
    logsBloom: Bytes
    status: Uint256
    to: ETHAddress | None
    transactionHash: ETHWord
    transactionIndex: Uint256
    type: Uint256


class BaseBlock(AutoEthable):
    logsBloom: Bytes | None = None
    number: Uint256 | None = None
    hash: ETHWord | None = None
    nonce: Uint256 | None = None
    parentHash: ETHWord
    sha3Uncles: ETHWord
    mixHash: ETHWord
    transactionsRoot: ETHWord
    stateRoot: ETHWord
    receiptsRoot: ETHWord
    miner: ETHAddress
    difficulty: Uint256
    totalDifficulty: Uint256
    extraData: Bytes
    size: Uint256
    gasLimit: Uint256
    gasUsed: Uint256
    timestamp: ETHDatetime
    uncles: list[ETHWord]
    baseFeePerGas: Uint256 | None = None


class FullBlock(BaseBlock):
    transactions: list[Transaction] = Field(default_factory=list)


class PartialBlock(BaseBlock):
    transactions: list[ETHWord] = Field(default_factory=list)


class WhisperFilter(AutoEthable):
    # noinspection PyUnresolvedReferences
    """Creates filter to notify, when client receives whisper message
    matching the filter options.

    Attributes:
        to (ETHAddress): Identity of the receiver. When
            present it will try to decrypt any incoming message if the
            client holds the private key to this identity.
        topics (list[ETHWord]): Array of DATA topics which the incoming
                message’s topics should match. You can use the following
                combinations:
                    [A, B] = A && B
                    [A, [B, C]] = A && (B || C)
                    [null, A, B] = ANYTHING && A && B null works as a wildcard
    """

    to: ETHAddress
    topics: list[ETHWord]


class Message(AutoEthable):
    # noinspection PyUnresolvedReferences
    """Whisper Message.

    Attributes:
        hash (ETHWord): The hash of the message.
        from (ETHAddress): The sender of the message, if specified.
        to (ETHAddress): The receiver of the message, if specified.
        expiry (Uint256): Time in seconds when this message should expire.
        ttl (Uint256): Time the message should float in the system in seconds.
        sent (Uint256): The unix timestamp when the message was sent.
        topics (list[ETHWord]): Topics the message contained.
        payload (ETHWord): The payload of the message.
        workProved (Uint256): The work this message required before it was send.
    """

    topics: list[ETHWord]
    payload: ETHWord
    ttl: Uint256
    priority: Uint256 = 1
    from_address: ETHAddress | None = None
    to: ETHAddress | None = None
    workProved: Uint256 | None = None
    sent: Uint256 | None = None
    expiry: Uint256 | None = None
    message_hash: ETHWord | None = None
