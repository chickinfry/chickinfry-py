"""Server-only readers and the shared budget for generated input decoders."""

import json
from collections.abc import Callable, Mapping
from typing import TypeVar, cast

from .server import MAX_REQUEST_BYTES, ServerError

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


class InputBudget:
    def __init__(self, value: Mapping[str, object]) -> None:
        # shortcut: ignored numbers use Python JSON sizes, align when numeric inputs open.
        # Lone surrogates count as JSON escapes without escaping valid Unicode.
        self.size = len(
            json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8", errors="backslashreplace"
            )
        )
        self._check()
        # Retain records so object identities cannot be reused during decoding.
        self._counts: dict[int, tuple[Mapping[str, object], int]] = {}

    def default(self, record: Mapping[str, object], key: str, literal: str) -> object:
        count = self._counts.get(id(record), (record, len(record)))[1]
        self.size += (
            len(
                json.dumps(key, ensure_ascii=False).encode(
                    "utf-8", errors="backslashreplace"
                )
            )
            + 1
            + (1 if count else 0)
            + len(literal.encode("utf-8", errors="backslashreplace"))
        )
        self._check()
        self._counts[id(record)] = (record, count + 1)
        return cast(object, json.loads(literal))

    def _check(self) -> None:
        if self.size > MAX_REQUEST_BYTES:
            raise ServerError("request_too_large", 413)


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
