import re
from dataclasses import dataclass
from itertools import islice


@dataclass(frozen=True, slots=True)
class FieldError:
    """A declared input path and its public validation code."""

    path: str
    code: str


def _string(value: object) -> str | None:
    return str.__str__(value) if isinstance(value, str) else None


def _message(value: object) -> str | None:
    try:
        text = _string(value)
        if text is None or re.search(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]", text):
            return None
        return text if len(text.encode("utf-8")) <= 1024 else None
    except Exception:
        return None


def _fields(
    value: object, declared: frozenset[str] | None = None
) -> tuple[FieldError, ...]:
    try:
        if isinstance(value, tuple):
            items = tuple(islice(tuple.__iter__(value), 33))
        elif isinstance(value, list):
            items = tuple(islice(list.__iter__(value), 33))
        else:
            return ()
        if len(items) > 32:
            return ()
        allowed = None
        if declared is not None:
            if not isinstance(declared, frozenset):
                return ()
            allowed = frozenset(_string(name) for name in frozenset.__iter__(declared))
        result: list[FieldError] = []
        field = r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*"
        for item in items:
            if isinstance(item, FieldError):
                path, code = _string(item.path), _string(item.code)
            elif isinstance(item, dict):
                entries = tuple(islice(dict.items(item), 3))
                record = {_string(key): value for key, value in entries}
                if len(entries) != 2 or set(record) != {"path", "code"}:
                    return ()
                path, code = _string(record["path"]), _string(record["code"])
            else:
                return ()
            if (
                path is None
                or code is None
                or len(path.encode("utf-8", errors="surrogatepass")) > 256
                or not re.fullmatch(
                    field + r"(?:\." + field + r"|\[(?:0|[1-9][0-9]*)\])*", path
                )
                or not re.fullmatch(r"[a-z_]{1,64}", code)
                or any(
                    int(index) > 4294967295
                    for index in re.findall(r"\[([0-9]+)\]", path)
                )
                or (allowed is not None and path not in allowed)
            ):
                return ()
            result.append(FieldError(path, code))
        return tuple(result)
    except Exception:
        return ()
