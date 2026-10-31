import ipaddress
import re
from urllib.parse import urlsplit

from .errors import _local_error


def canonical_origin(origin: str) -> str:
    if (
        not isinstance(origin, str)
        or not origin
        or any(ord(char) <= 32 or ord(char) == 127 for char in origin)
        or any(char in origin for char in "? #@\\%")
    ):
        raise _local_error("invalid_argument", "invalid_origin")
    result: str | None = None
    try:
        parsed = urlsplit(origin)
        host = parsed.hostname
        port = parsed.port
        if any(char in parsed.netloc for char in "[]") and not re.fullmatch(
            r"\[[^\[\]]+\](?::[0-9]+)?", parsed.netloc
        ):
            raise ValueError
        if (
            parsed.scheme in {"http", "https"}
            and host
            and parsed.path in {"", "/"}
            and not parsed.netloc.endswith(":")
            and (port is None or port > 0)
        ):
            address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                pass
            if parsed.scheme == "https" or (
                address
                and (
                    address.is_loopback
                    if isinstance(address, ipaddress.IPv4Address)
                    else address == ipaddress.IPv6Address("::1")
                )
            ):
                if address:
                    host = (
                        f"[{address.compressed}]"
                        if address.version == 6
                        else str(address)
                    )
                elif not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
                    raise ValueError
                default = 443 if parsed.scheme == "https" else 80
                suffix = f":{port}" if port and port != default else ""
                result = f"{parsed.scheme}://{host}{suffix}"
    except ValueError:
        pass
    if result is None:
        raise _local_error("invalid_argument", "invalid_origin")
    return result
