from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema

from eth_typing.enums import ForkName  # noqa: F401
from eth_typing.evm import BlockIdentifier  # noqa: F401

from fasteth.utils import coalesce_bytes

class ETHWord(bytes):
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls.validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: f"0x{v.hex()}",
                info_arg=False,
            )
        )

    @classmethod
    def validate(cls, val: Any) -> "ETHWord":
        return cls(coalesce_bytes(val, length=32))

class ETHAddress(bytes):
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls.validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: f"0x{v.hex()}",
                info_arg=False,
            )
        )

    @classmethod
    def validate(cls, val: Any) -> "ETHAddress":
        return cls(coalesce_bytes(val, length=20))

class MD5Hash(bytes):
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls.validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: f"0x{v.hex()}",
                info_arg=False,
            )
        )

    @classmethod
    def validate(cls, val: Any) -> "MD5Hash":
        return cls(coalesce_bytes(val, length=16))

class Bytes(bytes):
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls.validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: f"0x{v.hex()}",
                info_arg=False,
            )
        )

    @classmethod
    def validate(cls, val: Any) -> "Bytes":
        return cls(coalesce_bytes(val, enable_b64=True))

class HexBytes(bytes):
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls.validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: f"0x{v.hex()}",
                info_arg=False,
            )
        )

    @classmethod
    def validate(cls, val: Any) -> "HexBytes":
        return cls(coalesce_bytes(val))

class Uint256(int):
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(cls.validate)

    @classmethod
    def validate(cls, val: Any) -> "Uint256":
        if isinstance(val, (bytearray, memoryview, bytes)):
            return cls(int.from_bytes(val, byteorder="big", signed=False))
        elif isinstance(val, Decimal):
            return cls(int(val))
        elif isinstance(val, int):
            return cls(val)
        elif isinstance(val, str):
            return cls(int(val, base=16 if val.startswith("0x") else 10))
        else:
            raise TypeError("Value cannot be coerced into an integer")

class ETHDatetime(datetime):
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(cls.validate)

    @classmethod
    def validate(cls, val: Any) -> "ETHDatetime":
        if isinstance(val, (datetime, ETHDatetime)):
            return cls.fromtimestamp(val.timestamp())
        elif isinstance(val, (int, float)):
            return cls.fromtimestamp(val)
        elif isinstance(val, str):
            if val.startswith("0x"):
                return cls.fromtimestamp(int(val, base=16))
            return cls.fromisoformat(val)
        else:
            raise ValueError("Unknown format")


ETHBlockIdentifier = Literal["latest", "earliest", "pending"] | Uint256