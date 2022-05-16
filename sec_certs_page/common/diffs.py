from logging import getLogger
from typing import Mapping, Tuple

from flask import render_template
from jsondiff import symbols
from markupsafe import Markup, escape

from ..common.objformats import WorkingFormat

logger = getLogger(__name__)


def has_symbols(obj):
    def walk(o):
        if isinstance(o, dict):
            for k in o:
                if k in symbols._all_symbols_:
                    return True
                elif walk(o[k]):
                    return True
        elif isinstance(o, (tuple, list, set)):
            for k in o:
                if walk(k):
                    return True
        return False

    return walk(obj)


def apply_explicit_diff(dct, diff):
    """
    Apply an explicit diff constructed by jsondiff.

    :param dct: The object to apply on.
    :param diff: The diff.
    :return: A new object with the diff applied.
    """

    def walk(obj, d):
        if isinstance(obj, dict):
            c = dict(obj)
            if symbols.insert in d:
                c.update(dict(d[symbols.insert]))
            if symbols.update in d:
                for k, v in d[symbols.update].items():
                    if has_symbols(v):
                        c[k] = walk(c[k], v)
                    else:
                        c[k] = v
            if symbols.delete in d:
                for k in d[symbols.delete]:
                    del c[k]
            return c
        elif isinstance(obj, (list, tuple)):
            original_type = type(obj)
            c = list(obj)
            if symbols.delete in d:
                for pos in d[symbols.delete]:
                    c.pop(pos)
            if symbols.insert in d:
                for pos, value in d[symbols.insert]:
                    c.insert(pos, value)
            for k, v in d.items():
                if k is not symbols.delete and k is not symbols.insert:
                    k = int(k)
                    c[k] = walk(c[k], v)
            if original_type is not list:
                c = original_type(c)
            return c
        elif isinstance(obj, set):
            c = set(obj)
            if symbols.discard in d:
                for x in d[symbols.discard]:
                    c.discard(x)
            if symbols.add in d:
                for x in d[symbols.add]:
                    c.add(x)
            return c
        return obj

    return walk(dct, diff)


class DiffRenderer:
    collection: str
    diff_collection: str
    log_collection: str
    templates: Mapping[str, str]
    k2map: Mapping[str, Tuple[str, bool]]

    def render_diff(self, hashid, cert, diff, **kwargs) -> Markup:
        def render_code_template(template_str: str, vjson, **kws) -> Markup:
            template = Markup(template_str)
            return template.format(vjson=str(WorkingFormat(vjson).to_storage_format().to_json_mapping()), **kws)

        if diff["type"] == "new":
            return Markup(render_template(self.templates["new"], cert=diff["diff"], hashid=hashid, **kwargs))
        elif diff["type"] == "back":
            return Markup(render_template(self.templates["back"], cert=cert, hashid=hashid, **kwargs))
        elif diff["type"] == "remove":
            return Markup(render_template(self.templates["remove"], cert=cert, hashid=hashid, **kwargs))
        elif diff["type"] == "change":
            changes = []
            for k1, v1 in diff["diff"].items():
                if k1 == symbols.update:
                    for k2, v2 in v1.items():
                        details = []
                        if has_symbols(v2):
                            for k3, v3 in v2.items():
                                if k3 == symbols.update:
                                    if isinstance(v3, dict):
                                        for prop, val in v3.items():
                                            if has_symbols(val):
                                                detail = f"The {prop} property was updated."
                                                if symbols.insert in val:
                                                    detail = render_code_template(
                                                        "The {prop} property was updated, with the <code>{vjson}</code> values inserted.",
                                                        val[symbols.insert],
                                                        prop=str(prop),
                                                    )
                                                if symbols.discard in val:
                                                    detail = render_code_template(
                                                        "The {prop} property was updated, with the <code>{vjson}</code> values discarded.",
                                                        val[symbols.discard],
                                                        prop=str(prop),
                                                    )
                                                if symbols.update in val:
                                                    detail = render_code_template(
                                                        "The {prop} property was updated, with the <code>{vjson}</code> data.",
                                                        val[symbols.update],
                                                        prop=str(prop),
                                                    )
                                                if symbols.add in val:
                                                    detail = render_code_template(
                                                        "The {prop} property was updated, with the <code>{vjson}</code> values added.",
                                                        val[symbols.add],
                                                        prop=str(prop),
                                                    )
                                                details.append(detail)
                                            else:
                                                details.append(
                                                    render_code_template(
                                                        "The {prop} property was set to <code>{vjson}</code>.",
                                                        val,
                                                        prop=str(prop),
                                                    )
                                                )
                                elif k3 == symbols.insert:
                                    if has_symbols(v3):
                                        logger.error(f"Should not happen, ins: {k3}, {v3}")
                                    else:
                                        details.append(
                                            render_code_template(
                                                "The following values were inserted: <code>{vjson}</code>.", v3
                                            )
                                        )
                                elif k3 == symbols.delete:
                                    details.append(
                                        render_code_template(
                                            "The following properties were deleted: <code>{vjson}</code>.", v3
                                        )
                                    )
                                else:
                                    logger.error(f"Should not happen: {k3}, {v3}")
                        else:
                            details.append(render_code_template("The new value is <code>{vjson}</code>.", v2))
                        # Add the rendered change into the list.
                        changes.append((self.k2map.get(k2, (k2, False)), details))
            return Markup(
                render_template(self.templates["change"], cert=cert, changes=changes, hashid=hashid, **kwargs)
            )
        else:
            raise ValueError("Invalid diff type")
