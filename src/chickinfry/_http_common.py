import importlib.util
import json
import math
import re
import sys
import zlib
from collections.abc import Mapping
from http.cookiejar import Cookie, DefaultCookiePolicy
from typing import cast
from urllib.request import Request

from ._conformance import _observer
from .errors import ClientError, FieldError, OperationError

_REQUEST_LIMIT = 4 * 1024 * 1024
_RESPONSE_LIMIT = 1024 * 1024
_HEADERS = {"Accept-Encoding": "gzip, deflate", "Cache-Control": "no-store"}


def _check_environment() -> None:
    if (
        sys.platform in {"emscripten", "wasi"}
        or "pyodide" in sys.modules
        or importlib.util.find_spec("pyodide") is not None
    ):
        raise ClientError("unsupported_environment")


def _timeout(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (float, int))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ClientError("invalid_timeout")
    return float(value)


def _operation(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(
        r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*", value
    ):
        raise ClientError("invalid_operation")


def _reject_constant(value: str) -> object:
    raise ValueError


def _json_value(body: bytes) -> object:
    try:
        return cast(
            object, json.loads(body.decode("utf-8"), parse_constant=_reject_constant)
        )
    except (ValueError, UnicodeError, RecursionError):
        pass
    raise ClientError("invalid_response")


def _serialize(payload: bytes | Mapping[str, object]) -> bytes:
    body: bytes | None = None
    try:
        if isinstance(payload, bytes):
            body = payload
        elif isinstance(payload, Mapping):
            if any(not isinstance(key, str) for key in payload):
                raise ValueError
            body = json.dumps(
                dict(payload),
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        pass
    if body is None:
        raise ClientError("invalid_input")
    if len(body) > _REQUEST_LIMIT:
        raise ClientError("request_too_large")
    try:
        if isinstance(_json_value(body), dict):
            return body
    except ClientError:
        pass
    raise ClientError("invalid_input")


def _response(data: bytes, status: int) -> object:
    invalid = False
    try:
        value = _json_value(data)
    except ClientError:
        invalid = True
        value = None
    if not 200 <= status < 300:
        code = value.get("error") if isinstance(value, dict) else None
        valid = isinstance(code, str) and re.fullmatch(r"[a-z_]+", code) is not None
        failure = OperationError(
            code if valid and isinstance(code, str) else "invalid_response",
            status,
            cast(str | None, value.get("message"))
            if valid and isinstance(value, dict)
            else None,
            cast(tuple[FieldError, ...], value.get("fields"))
            if valid and isinstance(value, dict)
            else (),
        )
        failure._valid_error_envelope = valid
        raise failure
    if invalid:
        raise ClientError("invalid_response", status)
    return value


class _NoCookies(DefaultCookiePolicy):
    def set_ok(self, cookie: Cookie, request: Request) -> bool:
        return False

    def return_ok(self, cookie: Cookie, request: Request) -> bool:
        return False


class _Body:
    def __init__(self, encoding: str, status: int) -> None:
        self._status = status
        encoding = encoding.lower()
        if encoding not in {"identity", "gzip", "deflate"}:
            raise ClientError("invalid_response", status)
        self._decoder = (
            zlib.decompressobj(31 if encoding == "gzip" else 15)
            if encoding != "identity"
            else None
        )
        self._body = bytearray()
        self._raw_size = 0

    def feed(self, chunk: bytes) -> None:
        observation = _observer.get()
        self._raw_size += len(chunk)
        if self._raw_size > _RESPONSE_LIMIT:
            if observation is not None:
                observation.notify("limit", self)
            raise ClientError("response_too_large", self._status)
        decoded: bytes | None = None
        try:
            # Decompression bombs are also limited to the remaining budget plus one byte.
            decoded = (
                self._decoder.decompress(chunk, _RESPONSE_LIMIT - len(self._body) + 1)
                if self._decoder
                else chunk
            )
        except zlib.error:
            pass
        if decoded is None:
            raise ClientError("invalid_response", self._status)
        self._body.extend(decoded)
        if len(self._body) > _RESPONSE_LIMIT:
            if observation is not None:
                observation.notify("limit", self)
            raise ClientError("response_too_large", self._status)

    def finish(self) -> bytes:
        if self._decoder and (not self._decoder.eof or self._decoder.unused_data):
            raise ClientError("invalid_response", self._status)
        return bytes(self._body)
