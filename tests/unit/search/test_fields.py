from datetime import datetime

from sec_certs_page.common.search.fields import DateField, FloatField, IntField, OptionField, TextField
from sec_certs_page.common.search.query import detect_advanced_syntax, select_by_bitmask, select_by_id


def _result(res):
    return (res.ok, res.value, res.error)


def test_text_field():
    field = TextField()
    assert _result(field.parse("hello")) == (True, "hello", None)
    assert _result(field.parse("")) == (True, None, None)
    assert _result(field.parse(None)) == (True, None, None)


def test_int_field():
    field = IntField()
    assert _result(field.parse("42")) == (True, 42, None)
    assert _result(IntField(7).parse(None)) == (True, 7, None)
    assert _result(IntField(7).parse("")) == (True, 7, None)
    res = field.parse("abc")
    assert res.ok is False and res.value is None
    assert IntField(min=1).parse("0").ok is False
    assert IntField(max=10).parse("11").ok is False
    assert _result(IntField(min=1, max=10).parse("5")) == (True, 5, None)


def test_int_field_hex():
    field = IntField(base=16)
    assert _result(field.parse("ff")) == (True, 255, None)
    assert _result(field.parse("10")) == (True, 16, None)
    assert field.parse("xyz").ok is False


def test_float_field():
    field = FloatField()
    assert _result(field.parse("4.7")) == (True, 4.7, None)
    assert _result(field.parse("0")) == (True, 0.0, None)
    assert _result(field.parse(None)) == (True, None, None)
    assert _result(field.parse("")) == (True, None, None)
    assert _result(FloatField(default=1.0).parse(None)) == (True, 1.0, None)
    assert field.parse("abc").ok is False
    assert FloatField(min=0).parse("-1").ok is False
    assert FloatField(max=10).parse("11").ok is False
    assert _result(FloatField(min=0, max=10).parse("5.5")) == (True, 5.5, None)


def test_option_field():
    field = OptionField({"active", "archived"})
    assert _result(field.parse("active")) == (True, "active", None)
    assert field.parse("nope").ok is False
    assert _result(field.parse(None)) == (True, None, None)
    assert _result(OptionField({"name"}, "name").parse(None)) == (True, "name", None)


def test_date_field():
    field = DateField()
    assert _result(field.parse("2020-01-02")) == (True, datetime(2020, 1, 2), None)
    assert field.parse("not-a-date").ok is False
    assert _result(field.parse(None)) == (True, None, None)


def test_detect_advanced_syntax():
    assert detect_advanced_syntax("simple query") == set()
    assert "boolean_op" in detect_advanced_syntax("foo AND bar")
    assert "phrase" in detect_advanced_syntax('"foo bar"')
    assert "field_prefix" in detect_advanced_syntax("name:foo")
    assert "range" in detect_advanced_syntax("[2020-01-01 TO 2021-01-01]")
    assert "regex" in detect_advanced_syntax("/foo.*bar/")


def test_select_by_bitmask():
    options = ["a", "b", "c", "d"]
    assert select_by_bitmask(None, options) == options
    assert select_by_bitmask(0, options) == options
    assert select_by_bitmask(0b1010, options) == ["b", "d"]
    assert select_by_bitmask(0b0001, options) == ["a"]


def test_select_by_id():
    options = {"x": {"id": "a"}, "y": {"id": "b"}}
    selected = select_by_id("a", options)
    assert selected["x"]["selected"] is True
    assert selected["y"]["selected"] is False
    assert all(val["selected"] for val in select_by_id("", options).values())
    assert all(val["selected"] for val in select_by_id(None, options).values())
