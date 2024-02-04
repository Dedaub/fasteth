from datetime import datetime
from typing import Any, Literal, Annotated

from eth_typing.enums import ForkName  # noqa: F401
from eth_typing.evm import BlockIdentifier  # noqa: F401
from pydantic import PlainValidator

from fasteth.utils import coalesce_bytes

from functools import partial

ETHWord = Annotated[bytes, PlainValidator(partial(coalesce_bytes, length=32))]
ETHAddress = Annotated[bytes, PlainValidator(partial(coalesce_bytes, length=20))]
MD5Hash = Annotated[bytes, PlainValidator(partial(coalesce_bytes, length=16))]
Bytes = Annotated[bytes, PlainValidator(partial(coalesce_bytes, enable_b64=True))]
HexBytes = Annotated[bytes, PlainValidator(coalesce_bytes)]


def uint256_validate(val: Any):
    data: int
    if isinstance(val, (bytearray, memoryview, bytes)):
        data = int.from_bytes(val, byteorder="big", signed=False)
    elif isinstance(val, int):
        data = val
    elif isinstance(val, str):
        data = int(val, base=16 if val.startswith("0x") else 10)
    else:
        raise TypeError("Value cannot be coerced into an integer")
    return data


Uint256 = Annotated[int, PlainValidator(uint256_validate)]


def timedate_validate(val: Any):
    if isinstance(val, datetime):
        return datetime.fromtimestamp(val.timestamp())
    elif isinstance(val, (int, float)):
        return datetime.fromtimestamp(val)
    elif isinstance(val, str):
        if val.startswith("0x"):
            return datetime.fromtimestamp(int(val, base=16))
        return datetime.fromisoformat(val)
    else:
        raise ValueError("Unknown format")


ETHDatetime = Annotated[datetime, PlainValidator(timedate_validate)]


ETHBlockIdentifier = Literal["latest", "earliest", "pending"] | Uint256
