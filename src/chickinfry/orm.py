"""Generated databases connect table definitions and row decoders to repositories.

The generator owns the immutable Row/PrimaryKey dataclasses, Insert/Update
TypedDicts, typed columns, and repositories; this module owns SQL generation
and execution.
"""

import re
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timezone
from types import MappingProxyType
from typing import Generic, Literal, Protocol, TypeVar
from uuid import UUID

T = TypeVar("T")
R = TypeVar("R")
ScalarKind = Literal["id", "string", "integer", "date", "timestamp"]
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_STAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}(?::[0-9]{2})?)"
)
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


def parse_date(value: str) -> date:
    if not _DATE.fullmatch(value):
        raise ValueError("Date values must use YYYY-MM-DD.")
    return date.fromisoformat(value)


def parse_timestamp(value: str) -> datetime:
    if not _STAMP.fullmatch(value):
        raise ValueError("Timestamp must include a valid time and timezone.")
    normalized = value.replace(" ", "T")
    normalized = re.sub(r"([+-][0-9]{2})$", r"\1:00", normalized)
    # The standard parser accepts overflowing offset minutes, so reject them here first.
    if normalized[-6:-5] in ("+", "-") and (
        int(normalized[-5:-3]) > 23 or int(normalized[-2:]) > 59
    ):
        raise ValueError("Invalid timestamp offset.")
    return datetime.fromisoformat(normalized.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Database timestamps must have a timezone.")
    utc = value.astimezone(timezone.utc)
    fraction = f"{utc.microsecond:06d}".rstrip("0").ljust(3, "0")
    return (
        f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d}T"
        f"{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}.{fraction}Z"
    )


def encode_value(kind: ScalarKind, nullable: bool, value: object) -> object:
    if value is None:
        if nullable:
            return None
        raise ValueError("A non-null column cannot accept null.")
    if kind == "integer":
        if type(value) is not int or not -2147483648 <= value <= 2147483647:
            raise ValueError("Integer values must be signed 32-bit integers.")
        return value
    if not isinstance(value, str):
        raise ValueError("A string value is required.")
    if kind == "string":
        if "\0" in value:
            raise ValueError("A text column cannot contain NUL.")
        return value
    if kind == "id":
        if not _UUID.fullmatch(value):
            raise ValueError("An ID column requires a UUID.")
        return UUID(value)
    if kind == "date":
        return parse_date(value)
    if kind == "timestamp":
        return parse_timestamp(value)
    raise ValueError("Unsupported scalar kind.")


def decode_value(kind: ScalarKind, nullable: bool, value: object) -> object:
    if (
        sys.platform == "emscripten"
        and isinstance(value, str)
        and kind in ("id", "date", "timestamp")
    ):
        value = encode_value(kind, nullable, value)
    if value is None:
        return encode_value(kind, nullable, value)
    if kind == "date":
        if type(value) is not date:
            raise ValueError("Database dates must decode to dates.")
        return value.isoformat()
    if kind == "timestamp":
        if not isinstance(value, datetime):
            raise ValueError("Database timestamps must decode to datetimes.")
        return format_timestamp(value)
    if kind == "id":
        if not isinstance(value, UUID):
            raise ValueError("Database IDs must decode to UUIDs.")
        return str(value)
    return encode_value(kind, nullable, value)


class DatabasePort(Protocol):
    async def query(
        self, sql: str, parameters: Sequence[object]
    ) -> Sequence[Mapping[str, object]]: ...

    async def transaction(
        self, work: Callable[["DatabasePort"], Awaitable[T]]
    ) -> T: ...


class Database(Generic[T]):
    """Generated database subclasses pass their own constructor as the factory."""

    def __init__(
        self, port: DatabasePort, create_database: Callable[[DatabasePort], T]
    ) -> None:
        self._port, self._create_database = port, create_database

    async def transaction(self, work: Callable[[T], Awaitable[R]]) -> R:
        async def run(port: DatabasePort) -> R:
            return await work(self._create_database(port))

        return await self._port.transaction(run)


@dataclass(frozen=True, slots=True, eq=False)
class ColumnBase:
    name: str
    kind: ScalarKind
    nullable: bool = False

    def encode(self, value: object) -> object:
        return encode_value(self.kind, self.nullable, value)

    def decode(self, value: object) -> object:
        return decode_value(self.kind, self.nullable, value)


class Column(ColumnBase, Generic[T]):
    """Generated columns are declared as Column[scalar] to type-check condition values."""

    def equals(self, value: T) -> "Filter":
        return Filter("=", self, (value,))

    def not_equals(self, value: T) -> "Filter":
        return Filter("<>", self, (value,))

    def greater_than(self, value: T) -> "Filter":
        return Filter(">", self, (value,))

    def greater_than_or_equals(self, value: T) -> "Filter":
        return Filter(">=", self, (value,))

    def less_than(self, value: T) -> "Filter":
        return Filter("<", self, (value,))

    def less_than_or_equals(self, value: T) -> "Filter":
        return Filter("<=", self, (value,))

    def in_(self, values: Sequence[T]) -> "Filter":
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise ValueError("IN values must be a sequence.")
        return Filter("in", self, tuple(values))

    def is_null(self) -> "Filter":
        return Filter("is null", self)

    def is_not_null(self) -> "Filter":
        return Filter("is not null", self)

    def asc(self) -> "Order":
        return Order(self, "asc")

    def desc(self) -> "Order":
        return Order(self, "desc")


@dataclass(frozen=True, slots=True)
class Filter:
    operator: str
    column: ColumnBase | None = None
    values: tuple[object, ...] = ()
    children: tuple["Filter", ...] = ()


@dataclass(frozen=True, slots=True)
class Order:
    column: ColumnBase
    direction: Literal["asc", "desc"]


def and_(*filters: Filter) -> Filter:
    if not filters:
        raise ValueError("AND requires at least one condition.")
    return Filter("and", children=filters)


def or_(*filters: Filter) -> Filter:
    if not filters:
        raise ValueError("OR requires at least one condition.")
    return Filter("or", children=filters)


def not_(condition: Filter) -> Filter:
    return Filter("not", children=(condition,))


def quote_identifier(value: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("Invalid SQL identifier.")
    return '"' + value.replace('"', '""') + '"'


@dataclass(frozen=True, slots=True)
class Table:
    name: str
    columns: Mapping[str, ColumnBase]
    primary_key: tuple[str, ...]
    required_insert: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        quote_identifier(self.name)
        columns = dict(self.columns)
        if not columns or not self.primary_key:
            raise ValueError("Tables require columns and a primary key.")
        for keys in (self.primary_key, self.required_insert):
            if len(set(keys)) != len(keys) or any(key not in columns for key in keys):
                raise ValueError("Invalid table column list.")
        names = [column.name for column in columns.values()]
        for name in names:
            quote_identifier(name)
        if len(set(names)) != len(names):
            raise ValueError("Duplicate database column.")
        object.__setattr__(self, "columns", MappingProxyType(columns))

    def column(self, column: ColumnBase | None) -> ColumnBase:
        if column is None or not any(column is item for item in self.columns.values()):
            raise ValueError("Undeclared table columns cannot be used.")
        return column


def _compile(condition: Filter, table: Table, params: list[object]) -> str:
    if not isinstance(condition, Filter):
        raise ValueError("A typed filter is required.")
    op = condition.operator
    if op in ("and", "or", "not"):
        if not condition.children or (op == "not" and len(condition.children) != 1):
            raise ValueError("Invalid logical filter.")
        parts = [_compile(child, table, params) for child in condition.children]
        return f"not ({parts[0]})" if op == "not" else "(" + f" {op} ".join(parts) + ")"
    column = table.column(condition.column)
    name = quote_identifier(column.name)
    if op in ("is null", "is not null"):
        return f"{name} {op}"
    if op == "in":
        values = [column.encode(value) for value in condition.values]
        if not values:
            return "1 = 0"
        placeholders = []
        for value in values:
            if value is not None:
                params.append(value)
                placeholders.append(f"${len(params)}")
        parts = [f"{name} in ({', '.join(placeholders)})"] if placeholders else []
        if None in values:
            parts.append(f"{name} is null")
        return "(" + " or ".join(parts) + ")"
    if op not in ("=", "<>", ">", ">=", "<", "<=") or len(condition.values) != 1:
        raise ValueError("Unsupported comparison operator.")
    value = column.encode(condition.values[0])
    if value is None:
        if op not in ("=", "<>"):
            raise ValueError("NULL only supports equality comparisons.")
        return f"{name} is {'not ' if op == '<>' else ''}null"
    params.append(value)
    return f"{name} {op} ${len(params)}"


class Repository(Generic[R]):
    """Generated repositories pass input mappings through and decode every column into a Row."""

    def __init__(
        self, port: DatabasePort, table: Table, row: Callable[[Mapping[str, object]], R]
    ) -> None:
        self._port, self.table, self.row = port, table, row
        self._name = '"public".' + quote_identifier(table.name)
        self._select = ", ".join(
            quote_identifier(c.name) for c in table.columns.values()
        )

    def _rows(self, rows: Sequence[Mapping[str, object]]) -> list[R]:
        return [
            self.row(
                {
                    key: column.decode(row[column.name])
                    for key, column in self.table.columns.items()
                }
            )
            for row in rows
        ]

    def _record(self, value: Mapping[str, object], allowed: Sequence[str]) -> None:
        if not isinstance(value, Mapping) or any(key not in allowed for key in value):
            raise ValueError("Unknown input column or invalid input record.")

    def _key(self, key: Mapping[str, object]) -> Filter:
        self._record(key, self.table.primary_key)
        if any(name not in key for name in self.table.primary_key):
            raise ValueError("Missing primary key value.")
        return and_(
            *(
                Filter("=", self.table.columns[name], (key[name],))
                for name in self.table.primary_key
            )
        )

    async def find_many(
        self,
        *,
        where: Filter | None = None,
        order_by: Sequence[Order] = (),
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[R]:
        params: list[object] = []
        sql = f"select {self._select} from {self._name}"
        if where is not None:
            sql += " where " + _compile(where, self.table, params)
        if order_by:
            orders = []
            for order in order_by:
                column = self.table.column(order.column)
                if order.direction not in ("asc", "desc"):
                    raise ValueError("Unsupported sort direction.")
                orders.append(f"{quote_identifier(column.name)} {order.direction}")
            sql += " order by " + ", ".join(orders)
        for name, value in (("limit", limit), ("offset", offset)):
            if value is not None:
                if type(value) is not int or not 0 <= value <= 9007199254740991:
                    raise ValueError("Pagination requires non-negative safe integers.")
                params.append(value)
                sql += f" {name} ${len(params)}"
        return self._rows(await self._port.query(sql, params))

    async def find_by_id(self, key: Mapping[str, object]) -> R | None:
        rows = await self.find_many(where=self._key(key), limit=1)
        return rows[0] if rows else None

    async def insert(self, values: Mapping[str, object]) -> R:
        self._record(values, tuple(self.table.columns))
        if any(name not in values for name in self.table.required_insert):
            raise ValueError("Missing required insert column value.")
        keys = [name for name in self.table.columns if name in values]
        params = [self.table.columns[key].encode(values[key]) for key in keys]
        sql = f"insert into {self._name}"
        if keys:
            names = ", ".join(
                quote_identifier(self.table.columns[key].name) for key in keys
            )
            sql += (
                f" ({names}) values ("
                + ", ".join(f"${i + 1}" for i in range(len(keys)))
                + ")"
            )
        else:
            sql += " default values"
        rows = self._rows(
            await self._port.query(sql + " returning " + self._select, params)
        )
        if not rows:
            raise ValueError("Insert result row is missing.")
        return rows[0]

    async def update_if(
        self, key: Mapping[str, object], condition: Filter, patch: Mapping[str, object]
    ) -> R | None:
        allowed = tuple(
            key for key in self.table.columns if key not in self.table.primary_key
        )
        self._record(patch, allowed)
        if not patch:
            raise ValueError("No columns to update.")
        params: list[object] = []
        assignments = []
        for name, column in self.table.columns.items():
            if name in patch:
                params.append(column.encode(patch[name]))
                assignments.append(f"{quote_identifier(column.name)} = ${len(params)}")
        where = _compile(and_(self._key(key), condition), self.table, params)
        sql = f"update {self._name} set {', '.join(assignments)} where {where} returning {self._select}"
        rows = self._rows(await self._port.query(sql, params))
        return rows[0] if rows else None

    async def update(self, key: Mapping[str, object], patch: Mapping[str, object]) -> R:
        row = await self.update_if(key, self._key(key), patch)
        if row is None:
            raise ValueError("Update result row is missing.")
        return row

    async def delete(self, key: Mapping[str, object]) -> R | None:
        params: list[object] = []
        where = _compile(self._key(key), self.table, params)
        rows = self._rows(
            await self._port.query(
                f"delete from {self._name} where {where} returning {self._select}",
                params,
            )
        )
        return rows[0] if rows else None
