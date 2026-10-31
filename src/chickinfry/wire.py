"""Strict JSON reading helpers for generated clients; values are not coerced."""

from typing import cast

from .errors import ClientError


def read_record(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ClientError("internal")
    return cast(dict[str, object], value)


def read_string(value: object) -> str:
    if not isinstance(value, str):
        raise ClientError("internal")
    return value


def read_list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ClientError("internal")
    return cast(list[object], value)
