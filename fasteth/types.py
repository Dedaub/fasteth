from datetime import datetime
from typing import Any, Callable, Generator, Literal

from eth_typing.enums import ForkName  # noqa: F401
from eth_typing.evm import BlockIdentifier  # noqa: F401

from fasteth.utils import coalesce_bytes


class ETHWord(bytes):
    @classmethod
    def __get_validators__(cls) -> Generator[Callable[[Any], bytes], None, None]:
        yield cls.validate

    @classmethod
    def validate(cls, val: Any):
        return cls(coalesce_bytes(val, length=32))


class ETHAddress(bytes):
    @classmethod
    def __get_validators__(cls) -> Generator[Callable[[Any], bytes], None, None]:
        yield cls.validate

    @classmethod
    def validate(cls, val: Any):
        return cls(coalesce_bytes(val, length=20))


class MD5Hash(bytes):
    @classmethod
    def __get_validators__(cls) -> Generator[Callable[[Any], bytes], None, None]:
        yield cls.validate

    @classmethod
    def validate(cls, val: Any):
        return cls(coalesce_bytes(val, length=16))


class Bytes(bytes):
    @classmethod
    def __get_validators__(cls) -> Generator[Callable[[Any], bytes], None, None]:
        yield cls.validate

    @classmethod
    def validate(cls, val: Any):
        return cls(coalesce_bytes(val, enable_b64=True))


class Uint256(int):
    @classmethod
    def __get_validators__(cls) -> Generator[Callable[[Any], int], None, None]:
        yield cls.validate

    @classmethod
    def validate(cls, val: Any):
        data: int
        if isinstance(val, (bytearray, memoryview, bytes)):
            data = int.from_bytes(val, byteorder="big", signed=False)
        elif isinstance(val, int):
            data = val
        elif isinstance(val, str):
            data = int(val, base=16 if val.startswith("0x") else 10)
        else:
            raise TypeError("Value cannot be coerced into an integer")
        return cls(data)


class ETHDatetime(datetime):
    @classmethod
    def __get_validators__(cls) -> Generator[Callable[[Any], datetime], None, None]:
        yield cls.validate

    @classmethod
    def validate(cls, val: Any):
        if val.startswith("0x"):
            return cls.fromtimestamp(int(val, base=16))
        elif isinstance(val, (int, float)):
            return cls.fromtimestamp(val)
        elif isinstance(val, str):
            return cls.fromisoformat(val)
        else:
            raise ValueError("Unknown format")


ETHBlockIdentifier = Literal["latest", "earliest", "pending"] | Uint256
