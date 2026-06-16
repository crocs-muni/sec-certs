from typing import Any, Protocol
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ParseResult:
    ok: bool
    value: Any
    error: str | None = None


class FieldProtocol(Protocol):
    def parse(self, raw: str | None) -> ParseResult:
        ...


@dataclass
class IntField:
    default: int | None = None
    min: int | None = None
    max: int | None = None
    base: int = 10

    def parse(self, raw: str | None) -> ParseResult:
        if not raw:
            return ParseResult(True, self.default)

        try:
            value = int(raw, self.base)
        except ValueError:
            return ParseResult(False, None, "Expected an integer.")

        if self.min is not None and value < self.min:
            return ParseResult(False, None, f"Must be >= {self.min}.")
        if self.max is not None and value > self.max:
            return ParseResult(False, None, f"Must be <= {self.max}.")

        return ParseResult(True, value)


@dataclass
class OptionField:
    options: set[str]
    default: str | None = None

    def parse(self, raw: str | None) -> ParseResult:
        if not raw:
            return ParseResult(True, self.default)

        if raw not in self.options:
            return ParseResult(False, None, f"Must be one of: {', '.join(self.options)}.")

        return ParseResult(True, raw)


@dataclass
class DateField:
    default: datetime | None = None
    fmt: str = "%Y-%m-%d"

    def parse(self, raw: str | None) -> ParseResult:
        if not raw:
            return ParseResult(True, self.default)

        try:
            value = datetime.strptime(raw, self.fmt)
        except ValueError:
            return ParseResult(False, None, f"Expected date in format: {self.fmt}.")

        return ParseResult(True, value)


@dataclass
class TextField:
    def parse(self, raw: str | None) -> ParseResult:
        if raw == "":
            return ParseResult(True, None)
        return ParseResult(True, raw)
