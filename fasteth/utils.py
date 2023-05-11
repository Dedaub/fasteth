from base64 import b64decode
from typing import Any


def decode_hex(val: str) -> bytes:
    val = val.removeprefix("0x")
    # round to even length
    length = len(val) + (len(val) % 2)
    return bytes.fromhex(val.rjust(length, "0"))


def coalesce_bytes(
    val: Any, *, length: int | None = None, enable_b64: bool = False
) -> bytes:
    data: bytes
    if isinstance(val, (bytes, memoryview, bytearray)):
        # unify types
        data = bytes(val)
    elif isinstance(val, str):
        if enable_b64:
            try:
                data = b64decode(val)
            except Exception as e:
                if val.startswith("0x"):
                    data = decode_hex(val)
                else:
                    raise ValueError(
                        "Unable to decode data, base64 conversion failed and the data is not valid hex"
                    ) from e
        elif val.startswith("0x"):
            data = decode_hex(val)
        else:
            raise ValueError("Unable to decode data, input is not valid hex")
    else:
        raise ValueError(f"Unknown input type for binary data: {type(val).__name__}")

    # Pad data to desired length
    if length:
        if len(data) > length:
            raise ValueError("Desired data length exceeded")
        p = b"\x00" * (length - len(data))
        data = p + data

    return data
