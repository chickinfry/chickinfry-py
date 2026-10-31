"""Server-only readers and the shared budget for generated input decoders."""

import json
import math
from collections.abc import Callable, Mapping
from typing import TypeVar, cast

from .server import MAX_REQUEST_BYTES, OperationError

T = TypeVar("T")


def read_record(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError("An object with string keys is required.")
    return cast(dict[str, object], value)


def read_string(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("A string is required.")
    return value


def read_list(value: object, decode: Callable[[object], T]) -> list[T]:
    if not isinstance(value, list):
        raise ValueError("A list is required.")
    return [decode(item) for item in value]


def read_nullable(value: object, decode: Callable[[object], T]) -> T | None:
    return None if value is None else decode(value)


def _string_size(value: str) -> int:
    return len(
        json.dumps(value, ensure_ascii=False).encode("utf-8", errors="backslashreplace")
    )


def _number_size(value: int | float) -> int:
    try:
        number = float(value)
    except OverflowError:
        return 4
    if not math.isfinite(number):
        return 4
    if number == 0:
        return 1
    sign = 1 if number < 0 else 0
    mantissa, _, exponent = repr(abs(number)).partition("e")
    integer, _, fraction = mantissa.partition(".")
    raw = (integer + fraction).lstrip("0")
    digits = raw.rstrip("0")
    power = int(exponent or "0") - len(fraction) + len(raw) - len(digits)
    count, point = len(digits), len(digits) + power
    # ECMAScript Number::toString uses this decimal layout for binary64 values.
    if count <= point <= 21:
        return sign + point
    if 0 < point <= 21:
        return sign + count + 1
    if -6 < point <= 0:
        return sign + 2 - point + count
    return sign + count + (1 if count > 1 else 0) + 2 + len(str(abs(point - 1)))


def _json_size(value: object) -> int:
    size = 0
    pending: list[object] = [value]
    while pending:
        current = pending.pop()
        if current is None or current is True:
            size += 4
        elif current is False:
            size += 5
        elif isinstance(current, str):
            size += _string_size(current)
        elif isinstance(current, (int, float)):
            size += _number_size(current)
        elif isinstance(current, Mapping):
            size += 2 + max(0, len(current) - 1) + len(current)
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ValueError("A string key is required.")
                size += _string_size(key)
                pending.append(child)
        elif isinstance(current, list):
            size += 2 + max(0, len(current) - 1)
            pending.extend(current)
        else:
            raise ValueError("A JSON value is required.")
    return size


class InputBudget:
    def __init__(self, value: Mapping[str, object]) -> None:
        self.size = _json_size(value)
        self._check()
        # Retain records so object identities cannot be reused during decoding.
        self._counts: dict[int, tuple[Mapping[str, object], int]] = {}

    def default(self, record: Mapping[str, object], key: str, literal: str) -> object:
        count = self._counts.get(id(record), (record, len(record)))[1]
        self.size += (
            _string_size(key)
            + 1
            + (1 if count else 0)
            + len(literal.encode("utf-8", errors="backslashreplace"))
        )
        self._check()
        self._counts[id(record)] = (record, count + 1)
        return cast(object, json.loads(literal))

    def _check(self) -> None:
        if self.size > MAX_REQUEST_BYTES:
            raise OperationError("request_too_large", 413)


def read_field(
    record: Mapping[str, object],
    key: str,
    budget: InputBudget,
    default: str | None = None,
) -> object:
    if key in record:
        return record[key]
    if default is None:
        raise ValueError("A required field is missing.")
    return budget.default(record, key, default)
