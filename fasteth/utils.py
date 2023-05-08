from datetime import datetime
from typing import Any, Optional

from eth_utils.address import to_checksum_address, to_normalized_address
from eth_utils.conversions import to_bytes, to_hex, to_int, to_text

from fasteth import types as eth_types

to_py_converters: dict = {
    eth_types.Hash32: lambda x: to_bytes(None, x),
    eth_types.Address: lambda x: to_bytes(None, x),
    eth_types.HexAddress: to_normalized_address,
    eth_types.ChecksumAddress: to_checksum_address,
    eth_types.AnyAddress: lambda x: to_bytes(None, x),
    eth_types.HexStr: lambda x: to_text(None, x),
    eth_types.BlockNumber: lambda x: to_int(None, x),
    eth_types.BlockIdentifier: lambda x: to_int(None, x),
    eth_types.Data: lambda x: to_text(None, x),
    datetime: lambda x: datetime.fromtimestamp(to_int(None, x)),
    int: lambda x: to_int(None, x),
    str: lambda x: to_text(None, None, x),
    bytes: lambda x: to_bytes(None, x),
    Optional[eth_types.Hash32]: lambda x: to_bytes(None, x),
    Optional[eth_types.Address]: lambda x: to_bytes(None, x),
    Optional[eth_types.HexAddress]: to_normalized_address,
    Optional[eth_types.ChecksumAddress]: to_checksum_address,
    Optional[eth_types.AnyAddress]: lambda x: to_bytes(None, x),
    Optional[eth_types.HexStr]: lambda x: to_text(None, x),
    Optional[eth_types.BlockNumber]: lambda x: to_int(None, x),
    Optional[eth_types.BlockIdentifier]: lambda x: to_int(None, x),
    Optional[eth_types.Data]: lambda x: to_text(None, x),
    Optional[datetime]: lambda x: datetime.fromtimestamp(to_int(None, x)),
    Optional[int]: lambda x: to_int(None, x),
    Optional[str]: lambda x: to_text(None, None, x),
    Optional[bytes]: lambda x: to_bytes(None, x),
}

to_eth_converters: dict = {
    eth_types.Hash32: to_hex,
    eth_types.Address: to_hex,
    eth_types.HexAddress: to_normalized_address,
    eth_types.ChecksumAddress: to_checksum_address,
    eth_types.AnyAddress: to_hex,
    eth_types.HexStr: lambda x: to_hex(None, None, x),
    eth_types.BlockNumber: to_hex,
    eth_types.BlockIdentifier: to_hex,
    eth_types.Data: lambda x: to_hex(None, None, x),
    datetime: lambda x: to_hex(x.timestamp()),
    int: to_hex,
    str: lambda x: to_hex(None, None, x),
    bytes: to_hex,
    Optional[eth_types.Hash32]: to_hex,
    Optional[eth_types.Address]: to_hex,
    Optional[eth_types.HexAddress]: to_normalized_address,
    Optional[eth_types.ChecksumAddress]: to_checksum_address,
    Optional[eth_types.AnyAddress]: to_hex,
    Optional[eth_types.HexStr]: lambda x: to_hex(None, None, x),
    Optional[eth_types.BlockNumber]: to_hex,
    Optional[eth_types.BlockIdentifier]: to_hex,
    Optional[eth_types.Data]: lambda x: to_hex(None, None, x),
    Optional[datetime]: lambda x: to_hex(x.timestamp()),
    Optional[int]: to_hex,
    Optional[str]: lambda x: to_hex(None, None, x),
    Optional[bytes]: to_hex,
}


def result_truthiness(result: str) -> Any:
    """Parse string to bool, or if there is no bool, return the original."""
    if type(result) == str:
        # Results for True/False sometimes return as string.
        if result == "False":
            return False
        elif result == "True":
            return True
        else:
            return result
    return result
