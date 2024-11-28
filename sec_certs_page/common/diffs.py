from difflib import SequenceMatcher
from itertools import zip_longest
from logging import getLogger
from typing import Any, Mapping, Tuple

from flask import render_template, url_for
from jsondiff import symbols
from markupsafe import Markup, escape
from sec_certs.cert_rules import cc_rules, fips_rules
from sec_certs.utils.extract import scheme_frontpage_functions

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
                                elif k3 == symbols.add:
                                    if has_symbols(v3):
                                        logger.error(f"Should not happen, add: {k3}, {v3}")
                                    else:
                                        details.append(
                                            render_code_template(
                                                "The following values were added: <code>{vjson}</code>.", v3
                                            )
                                        )
                                elif k3 == symbols.discard:
                                    if has_symbols(v3):
                                        logger.error(f"Should not happen, discard: {k3}, {v3}")
                                    else:
                                        details.append(
                                            render_code_template(
                                                "The following values were removed: <code>{vjson}</code>.", v3
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


def bold(a: Any) -> Markup:
    return Markup(f"<b>{escape(a)}</b>")


def normal(a: Any) -> Markup:
    return escape(a)


def comma_separate(values):
    return Markup(", ".join(map(str, values)))


def diff_none():
    return None


def diff_int():
    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        return (normal if equal else bold)(a)

    return compare, render


def diff_bool():
    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        return (normal if equal else bold)(a)

    return compare, render


def diff_str():
    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        if equal:
            return normal(a)
        if a is None:
            return Markup("")
        if b is None:
            return bold(a)
        matcher = SequenceMatcher(lambda x: x == " ", a, b)
        if matcher.ratio() < 0.2:
            return bold(a)
        result = ""
        prev_end = 0
        for start_a, start_b, n in matcher.get_matching_blocks():
            end = start_a + n
            if n == 1:
                # add a[prev_end:end] to result in bold (skip single character matches)
                result += bold(a[prev_end:end])
            else:
                # add a[prev_end:start_a] to result in normal
                result += bold(a[prev_end:start_a])
                # add a[start_a:start_a+n] to result in bold
                result += normal(a[start_a:end])
            # set prev_end to start_a+n
            prev_end = end
        return Markup(result)

    return compare, render


def diff_ident():
    compare_str, render_str = diff_str()

    def render(equal: bool, a: Any, b: Any) -> Markup:
        if equal:
            return Markup(f'<span title="{escape(a)}" data-bs-toggle="tooltip">Equal</span>')
        else:
            return Markup(f'<span title="{escape(a)}" data-bs-toggle="tooltip"><b>Different</b></span>')

    return compare_str, render


def diff_url():
    compare_str, render_str = diff_str()

    def render(equal: bool, a: Any, b: Any) -> Markup:
        if a:
            return Markup(f'<a href="{a}" target="_blank" rel="noopener">{render_str(equal, a, b)}</a>')
        else:
            return render_str(equal, a, b)

    return compare_str, render


def diff_set(elem_diff):
    _, render_elem = elem_diff

    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        return comma_separate([render_elem(elem in b if b else False, elem, None) for elem in a]) if a else escape("{}")

    return compare, render


def diff_list(elem_diff):
    compare_elem, render_elem = elem_diff

    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        return (
            comma_separate(
                [
                    render_elem(compare_elem(a_elem, b_elem), a_elem, b_elem)
                    for a_elem, b_elem in zip_longest(a, b if b else [])
                ]
            )
            if a
            else escape("[]")
        )

    return compare, render


def diff_keywords():
    def compare(a, b):
        return a == b

    compare_set, render_set = diff_set(diff_str())
    compare_list, render_list = diff_list(diff_str())
    compare_int, render_int = diff_int()

    def render(equal: bool, a: Any, b: Any) -> Markup:
        def render_dict(one, other):
            if not one:
                return Markup("")
            if not other:
                other = {}
            items = []
            for key, val in sorted(one.items()):
                label = (bold if key not in other else normal)(key)
                change = False
                span = False
                if isinstance(val, dict):
                    other_val = other.get(key, {})
                    item = render_dict(val, other_val)
                elif isinstance(val, set):
                    other_val = other.get(key, set())
                    item = render_set(compare_set(val, other_val), val, other_val)
                elif isinstance(val, list):
                    other_val = other.get(key, [])
                    item = render_list(compare_list(val, other_val), val, other_val)
                else:
                    other_val = other.get(key, None)
                    item = render_int(compare_int(val, other_val), val, other_val)
                    span = True
                    change = val != other_val
                if span:
                    if change:
                        line = f'<span class="change">{label}: {item}</span>'
                    else:
                        line = f"<span>{label}: {item}</span>"
                else:
                    line = f"{label}: {item}"
                items.append(Markup(f"<li>{line}</li>"))
            item_string = "\n".join(items)
            return Markup(f"<ul>{item_string}</ul>")

        return render_dict(a, b)

    return compare, render


def diff_pdf_meta():
    metas = {
        "pdf_is_encrypted": diff_bool(),
        "pdf_number_of_pages": diff_int(),
        "pdf_file_size_bytes": diff_int(),
        "pdf_hyperlinks": diff_set(diff_url()),
    }

    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        return render_dict(a, b, metas=metas)

    return compare, render


def diff_date():
    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        return (normal if equal else bold)(escape(a.strftime("%d.%m.%Y")) if a is not None else Markup())

    return compare, render


def diff_cve():
    compare_str, render_str = diff_str()

    def render(equal: bool, a: Any, b: Any) -> Markup:
        return Markup(
            f"<a href=\"{url_for('vuln.cve', cve_id=a)}\" title=\"Navigate to CVE\" data-bs-toggle=\"tooltip\">{render_str(equal, a, b)}</a>"
        )

    return compare_str, render


def diff_cpe():
    compare_str, render_str = diff_str()

    def render(equal: bool, a: Any, b: Any) -> Markup:
        return Markup(
            f"<a href=\"{url_for('vuln.cpe', cpe_id=a)}\"title=\"Navigate to CPE\" data-bs-toggle=\"tooltip\">{render_str(equal, a, b)}</a>"
        )

    return compare_str, render


def diff_fips_cert_id():
    compare_str, render_str = diff_str()

    def render(equal: bool, a: Any, b: Any) -> Markup:
        if a:
            return Markup(
                f"<a href=\"{url_for('fips.entry_id', cert_id=a)}\" title=\"Navigate to cert by ID\" data-bs-toggle=\"tooltip\">{render_str(equal, a, b)}</a>"
            )
        else:
            return render_str(equal, a, b)

    return compare_str, render


def diff_fips_dgst():
    compare_str, render_str = diff_str()

    def render(equal: bool, a: Any, b: Any) -> Markup:
        return Markup(
            f"<a href=\"{url_for('fips.entry', hashid=a)}\" title=\"Navigate to cert by digest\" data-bs-toggle=\"tooltip\">{render_str(equal, a, b)}</a>"
        )

    return compare_str, render


def diff_fips_validation_history():
    metas = {
        "_type": diff_none(),
        "date": diff_date(),
        "validation_type": diff_str(),
        "lab": diff_str(),
    }

    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        items = []
        for update_a, update_b in zip(a, b):
            items.append(render_dict(update_a, update_b, metas=metas))
        return Markup("<hr/>\n".join(items))

    return compare, render


def diff_cc_cert_id(link: bool = True):
    compare_str, render_str = diff_str()

    def render(equal: bool, a: Any, b: Any) -> Markup:
        if a and link:
            return Markup(
                f"<a href=\"{url_for('cc.entry_id', cert_id=a)}\" title=\"Navigate to cert by ID\" data-bs-toggle=\"tooltip\">{render_str(equal, a, b)}</a>"
            )
        else:
            return render_str(equal, a, b)

    return compare_str, render


def diff_cc_dgst():
    compare_str, render_str = diff_str()

    def render(equal: bool, a: Any, b: Any) -> Markup:
        return Markup(
            f"<a href=\"{url_for('cc.entry', hashid=a)}\" title=\"Navigate to cert by digest\" data-bs-toggle=\"tooltip\">{render_str(equal, a, b)}</a>"
        )

    return compare_str, render


def diff_cc_sar():
    _, render_str = diff_str()

    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        return render_str(equal, f"{a['family']}.{a['level']}", None)

    return compare, render


def render_dict(a, b, metas=None):
    compare_str, render_str = diff_str()

    if not a:
        return Markup("")
    if not b:
        b = {}
    items = []
    for key, val in sorted(a.items()):
        label = (bold if key not in b else normal)(key)
        other_val = b.get(key, None)
        change = val != other_val
        if metas and key in metas:
            differ = metas[key]
            if differ is None:
                continue
            compare_meta, render_meta = differ
            item = render_meta(compare_meta(val, other_val), val, other_val)
        else:
            item = render_str(compare_str(val, other_val), val, other_val)
        if change:
            line = f'<span class="change">{label}: {item}</span>'
        else:
            line = f"<span>{label}: {item}</span>"
        items.append(Markup(f"<li>{line}</li>"))

    item_string = "\n".join(items)
    return Markup(f"<ul>{item_string}</ul>")


def diff_cc_frontpage():
    metas = {
        "cert_id": diff_cc_cert_id(link=False),
        "cc_security_level": diff_str(),
        "cc_version": diff_str(),
        "cert_lab": diff_str(),
        "cert_item": diff_str(),
        "cert_item_version": diff_str(),
        "developer": diff_str(),
        "ref_protection_profiles": diff_str(),
    }

    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        items = []
        for scheme in scheme_frontpage_functions:
            adata = a.get(scheme) if a is not None else None
            bdata = b.get(scheme) if b is not None else None
            if adata is None and bdata is None:
                continue
            item = render_dict(adata, bdata, metas=metas)
            items.append(Markup(f"<li>{scheme}: {item}</li>"))
        item_string = "\n".join(items)
        return Markup(f"<ul>{item_string}</ul>")

    return compare, render


def diff_cc_scheme_data():
    base_metas = {
        "url": diff_url(),
        "report_link": diff_url(),
        "target_link": diff_url(),
        "cert_link": diff_url(),
        **{f"{t}_date": diff_date() for t in ("certification", "expiration", "revision", "acceptance")},
    }
    metas = {"enhanced": (lambda a, b: a == b, lambda equal, a, b: render_dict(a, b, metas=base_metas)), **base_metas}

    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        return render_dict(a, b, metas=metas)

    return compare, render


def diff_cc_mus():
    metas = {
        "_type": diff_none(),
        "maintenance_date": diff_date(),
        "maintenance_title": diff_str(),
        "maintenance_report_link": diff_url(),
        "maintenance_st_link": diff_url(),
    }

    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        items = []
        for mu in a:
            if mu not in b:
                other = {}
            else:
                other = mu
            items.append(render_dict(mu, other, metas=metas))
        return Markup("<hr/>\n".join(items))

    return compare, render


def diff_cc_pps():
    metas = {
        "_type": diff_none(),
        "pp_name": diff_str(),
        "pp_eal": diff_str(),
        "pp_link": diff_url(),
        "pp_ids": diff_set(diff_str()),
    }

    def compare(a, b):
        return a == b

    def render(equal: bool, a: Any, b: Any) -> Markup:
        items = []
        for pp in a:
            if pp not in b:
                other = {}
            else:
                other = pp
            items.append(render_dict(pp, other, metas=metas))
        return Markup("<hr/>\n".join(items))

    return compare, render


cc_diff_method = {
    "_type": diff_none(),
    "name": diff_str(),
    "category": diff_str(),
    "scheme": diff_str(),
    "status": diff_str(),
    "not_valid_after": diff_date(),
    "not_valid_before": diff_date(),
    "cert_link": diff_url(),
    "report_link": diff_url(),
    "st_link": diff_url(),
    "manufacturer": diff_str(),
    "manufacturer_web": diff_url(),
    "security_level": diff_set(diff_str()),
    "dgst": diff_cc_dgst(),
    "heuristics": {
        "_type": diff_none(),
        "annotated_references": diff_none(),
        "cert_id": diff_cc_cert_id(),
        "cert_lab": diff_list(diff_str()),
        "cpe_matches": diff_set(diff_cpe()),
        "verified_cpe_matches": diff_set(diff_cpe()),
        "related_cves": diff_set(diff_cve()),
        "direct_transitive_cves": diff_set(diff_cve()),
        "indirect_transitive_cves": diff_set(diff_cve()),
        "extracted_sars": diff_set(diff_cc_sar()),
        "extracted_versions": diff_set(diff_str()),
        "prev_certificates": diff_set(diff_cc_cert_id()),
        "next_certificates": diff_set(diff_cc_cert_id()),
        "report_references": {
            "_type": diff_none(),
            "directly_referenced_by": diff_set(diff_cc_cert_id()),
            "directly_referencing": diff_set(diff_cc_cert_id()),
            "indirectly_referenced_by": diff_set(diff_cc_cert_id()),
            "indirectly_referencing": diff_set(diff_cc_cert_id()),
        },
        "scheme_data": diff_cc_scheme_data(),
        "st_references": {
            "_type": diff_none(),
            "directly_referenced_by": diff_set(diff_cc_cert_id()),
            "directly_referencing": diff_set(diff_cc_cert_id()),
            "indirectly_referenced_by": diff_set(diff_cc_cert_id()),
            "indirectly_referencing": diff_set(diff_cc_cert_id()),
        },
    },
    "maintenance_updates": diff_cc_mus(),
    "protection_profiles": diff_cc_pps(),
    "pdf_data": {
        "_type": diff_none(),
        "cert_filename": diff_str(),
        "cert_frontpage": diff_cc_frontpage(),
        "cert_keywords": {kw_group: diff_keywords() for kw_group in cc_rules},
        "cert_metadata": diff_pdf_meta(),
        "report_filename": diff_str(),
        "report_frontpage": diff_cc_frontpage(),
        "report_keywords": {kw_group: diff_keywords() for kw_group in cc_rules},
        "report_metadata": diff_pdf_meta(),
        "st_filename": diff_str(),
        "st_frontpage": diff_cc_frontpage(),
        "st_keywords": {kw_group: diff_keywords() for kw_group in cc_rules},
        "st_metadata": diff_pdf_meta(),
    },
    "state": {
        "_type": diff_none(),
        "cert": {
            "_type": diff_none(),
            "convert_garbage": diff_bool(),
            "convert_ok": diff_bool(),
            "download_ok": diff_bool(),
            "extract_ok": diff_bool(),
            "pdf_hash": diff_ident(),
            "txt_hash": diff_ident(),
        },
        "report": {
            "_type": diff_none(),
            "convert_garbage": diff_bool(),
            "convert_ok": diff_bool(),
            "download_ok": diff_bool(),
            "extract_ok": diff_bool(),
            "pdf_hash": diff_ident(),
            "txt_hash": diff_ident(),
        },
        "st": {
            "_type": diff_none(),
            "convert_garbage": diff_bool(),
            "convert_ok": diff_bool(),
            "download_ok": diff_bool(),
            "extract_ok": diff_bool(),
            "pdf_hash": diff_ident(),
            "txt_hash": diff_ident(),
        },
    },
}

fips_diff_method = {
    "_type": diff_none(),
    "cert_id": diff_fips_cert_id(),
    "dgst": diff_fips_dgst(),
    "heuristics": {
        "_type": diff_none(),
        "algorithms": diff_set(diff_str()),
        "cpe_matches": diff_set(diff_cpe()),
        "direct_transitive_cves": diff_set(diff_cve()),
        "extracted_versions": diff_set(diff_str()),
        "indirect_transitive_cves": diff_set(diff_cve()),
        "module_processed_references": {
            "_type": diff_none(),
            "directly_referenced_by": diff_set(diff_fips_cert_id()),
            "directly_referencing": diff_set(diff_fips_cert_id()),
            "indirectly_referenced_by": diff_set(diff_fips_cert_id()),
            "indirectly_referencing": diff_set(diff_fips_cert_id()),
        },
        "module_prunned_references": diff_set(diff_int()),
        "policy_processed_references": {
            "_type": diff_none(),
            "directly_referenced_by": diff_set(diff_fips_cert_id()),
            "directly_referencing": diff_set(diff_fips_cert_id()),
            "indirectly_referenced_by": diff_set(diff_fips_cert_id()),
            "indirectly_referencing": diff_set(diff_fips_cert_id()),
        },
        "policy_prunned_references": diff_set(diff_int()),
        "related_cves": diff_set(diff_cve()),
        "verified_cpe_matches": diff_set(diff_cpe()),
    },
    "pdf_data": {
        "_type": diff_none(),
        "keywords": {kw_group: diff_keywords() for kw_group in fips_rules},
        "policy_metadata": diff_pdf_meta(),
    },
    "state": {
        "_type": diff_none(),
        "module_download_ok": diff_bool(),
        "module_extract_ok": diff_bool(),
        "policy_convert_garbage": diff_bool(),
        "policy_convert_ok": diff_bool(),
        "policy_download_ok": diff_bool(),
        "policy_extract_ok": diff_bool(),
        "policy_pdf_hash": diff_ident(),
        "policy_txt_hash": diff_ident(),
    },
    "web_data": {
        "_type": diff_none(),
        "caveat": diff_str(),
        "certificate_pdf_url": diff_url(),
        "date_sunset": diff_date(),
        "description": diff_str(),
        "embodiment": diff_str(),
        "exceptions": diff_list(diff_str()),
        "fw_versions": diff_list(diff_str()),
        "historical_reason": diff_str(),
        "hw_versions": diff_list(diff_str()),
        "level": diff_int(),
        "mentioned_certs": diff_keywords(),
        "module_name": diff_str(),
        "module_type": diff_str(),
        "revoked_link": diff_url(),
        "revoked_reason": diff_str(),
        "standard": diff_str(),
        "status": diff_str(),
        "sw_versions": diff_str(),
        "tested_conf": diff_list(diff_str()),
        "validation_history": diff_fips_validation_history(),
        "vendor": diff_str(),
        "vendor_url": diff_url(),
    },
}


def render_compare(one, other, diff_method):
    changes = {}

    def walk(tree, a, b, path=()):
        for key, value in tree.items():
            new_path = path + (key,)
            if isinstance(value, dict):
                subtree = value
                if a is None or b is None:
                    continue
                walk(subtree, a[key], b[key], new_path)
            else:
                differ = value
                if differ is None:
                    # Simple ignore
                    continue
                else:
                    compare, render = differ
                    aval = a[key] if a is not None and key in a else None
                    bval = b[key] if b is not None and key in b else None
                    equal = compare(aval, bval)
                    left, right = render(equal, aval, bval), render(equal, bval, aval)
                    changes[new_path] = {"left": left, "right": right, "equal": equal}

    walk(diff_method, one, other)
    return changes
