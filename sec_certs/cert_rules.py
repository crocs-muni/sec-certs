import re
from pathlib import Path
from typing import Dict, Set, Tuple

import yaml

REGEXEC_SEP = r"[ ,;\]”)(]"

# This ignores ACM and AMA SARs that are present in CC version 2
SARS_IMPLIED_FROM_EAL: Dict[str, Set[Tuple[str, int]]] = {
    "EAL1": {
        ("ADV_FSP", 1),
        ("AGD_OPE", 1),
        ("AGD_PRE", 1),
        ("ALC_CMC", 1),
        ("ALC_CMS", 1),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 1),
        ("ASE_REQ", 1),
        ("ASE_TSS", 1),
        ("ATE_IND", 1),
        ("AVA_VAN", 1),
    },
    "EAL2": {
        ("ADV_ARC", 1),
        ("ADV_TDS", 1),
        ("AGD_OPE", 1),
        ("AGD_PRE", 1),
        ("ALC_CMC", 2),
        ("ALC_CMS", 2),
        ("ALC_DEL", 1),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 2),
        ("ASE_REQ", 2),
        ("ASE_SPD", 1),
        ("ASE_TSS", 1),
        ("ATE_COV", 1),
        ("ATE_FUN", 1),
        ("ATE_IND", 2),
        ("AVA_VAN", 2),
    },
    "EAL3": {
        ("ADV_ARC", 1),
        ("ADV_FSP", 3),
        ("ADV_TDS", 2),
        ("AGD_PRE", 1),
        ("ALC_CMC", 3),
        ("ALC_CMS", 3),
        ("ALC_DEL", 1),
        ("ALC_DVS", 1),
        ("ALC_LCD", 1),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 2),
        ("ASE_REQ", 2),
        ("ASE_SPD", 1),
        ("ASE_TSS", 1),
        ("ATE_COV", 2),
        ("ATE_DPT", 1),
        ("ATE_FUN", 1),
        ("ATE_IND", 2),
        ("AVA_VAN", 2),
    },
    "EAL4": {
        ("ADV_ARC", 1),
        ("ADV_FSP", 4),
        ("ADV_IMP", 1),
        ("ADV_TDS", 3),
        ("AGD_OPE", 1),
        ("AGD_PRE", 1),
        ("ALC_CMC", 4),
        ("ALC_CMS", 4),
        ("ALC_DEL", 1),
        ("ALC_DVS", 1),
        ("ALC_LCD", 1),
        ("ALC_TAT", 1),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 2),
        ("ASE_REQ", 2),
        ("ASE_SPD", 1),
        ("ASE_TSS", 1),
        ("ATE_COV", 2),
        ("ATE_DPT", 1),
        ("ATE_FUN", 1),
        ("ATE_IND", 2),
        ("AVA_VAN", 3),
    },
    "EAL5": {
        ("ADV_ARC", 1),
        ("ADV_FSP", 5),
        ("ADV_IMP", 1),
        ("ADV_INT", 2),
        ("ADV_TDS", 4),
        ("AGD_OPE", 1),
        ("AGD_PRE", 1),
        ("ALC_CMC", 4),
        ("ALC_CMS", 5),
        ("ALC_DEL", 1),
        ("ALC_DVS", 1),
        ("ALC_LCD", 1),
        ("ALC_TAT", 2),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 2),
        ("ASE_REQ", 2),
        ("ASE_SPD", 1),
        ("ASE_TSS", 1),
        ("ATE_COV", 2),
        ("ATE_DPT", 3),
        ("ATE_FUN", 1),
        ("ATE_IND", 2),
        ("AVA_VAN", 4),
    },
    "EAL6": {
        ("ADV_ARC", 1),
        ("ADV_FSP", 5),
        ("ADV_IMP", 2),
        ("ADV_INT", 3),
        ("ADV_SPM", 1),
        ("ADV_TDS", 5),
        ("AGD_OPE", 1),
        ("AGD_PRE", 1),
        ("ALC_CMC", 5),
        ("ALC_CMS", 5),
        ("ALC_DEL", 1),
        ("ALC_DVS", 2),
        ("ALC_LCD", 1),
        ("ALC_TAT", 3),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 2),
        ("ASE_REQ", 2),
        ("ASE_SPD", 1),
        ("ASE_TSS", 1),
        ("ATE_COV", 3),
        ("ATE_DPT", 3),
        ("ATE_FUN", 2),
        ("ATE_IND", 2),
        ("AVA_VAN", 5),
    },
    "EAL7": {
        ("ADV_ARC", 1),
        ("ADV_FSP", 6),
        ("ADV_IMP", 2),
        ("ADV_INT", 3),
        ("ADV_SPM", 1),
        ("ADV_TDS", 6),
        ("AGD_OPE", 1),
        ("AGD_PRE", 1),
        ("ALC_CMC", 5),
        ("ALC_CMS", 5),
        ("ALC_DEL", 1),
        ("ALC_DVS", 2),
        ("ALC_LCD", 2),
        ("ALC_TAT", 3),
        ("ASE_CCL", 1),
        ("ASE_ECD", 1),
        ("ASE_INT", 1),
        ("ASE_OBJ", 2),
        ("ASE_REQ", 2),
        ("ASE_SPD", 1),
        ("ASE_TSS", 1),
        ("ATE_COV", 3),
        ("ATE_DPT", 4),
        ("ATE_FUN", 2),
        ("ATE_IND", 3),
        ("AVA_VAN", 5),
    },
}

security_level_csv_scan = r"EAL[1-7]\+?"

rules_fips_remove_algorithm_ids = [
    # --- HMAC(-SHA)(-1) - (bits) (method) ((hardware/firmware cert) #id) ---
    # + added (and #id) everywhere
    r"HMAC(?:[- –]*SHA)?(?:[- –]*1)?[– -]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[, ]*?\(?(?: |hardware|firmware)*?[\s(\[]*?(?:#|cert\.?|Cert\.?|Certificate|sample)?[\s#]*?)?[\s#]*?(\d{1,4})(?:[\s#]*and[\s#]*\d+)?",
    # --- same as above, without hw or fw ---
    r"HMAC(?:-SHA)?(?:-1)?[ -]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[, ]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{1,4})",
    # --- SHS/A - (bits) (method) ((cert #) numbers) ---
    r"SH[SA][-– 123]*(?:;|\/|160|224|256|384|512)?(?:[\s(\[]*?(?:KAT|[Bb]yte [Oo]riented)*?[\s,]*?[\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{1,4})(?:\)?\[#?\d+\])?(?:[\s#]*?and[\s#]*?\d+)?",
    # --- RSA (bits) (method) ((cert #)) ---
    r"RSA(?:[-– ]*(?:;|\/|512|768|1024|1280|1536|2048|3072|4096|8192)\s\(\[]*?(?:(?:;|\/|KAT|Verify|PSS|\s)*?)?[\s,]*?[\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{1,4})",
    # --- RSA (SSA) (PKCS) (version) (#) ---
    r"(?:RSA)?[-– ]?(?:SSA)?[- ]?PKCS\s?#?\d(?:-[Vv]1_5| [Vv]1[-_]5)?[\s#]*?(\d{1,4})?",
    # --- AES (bits) (method) ((cert #)) ---
    r"AES[-– ]*((?: |;|\/|bit|key|128|192|256|CBC)*(?: |\/|;|[Dd]ecrypt|[Ee]ncrypt|KAT|CMAC|CTR|GCM|IV|CBC)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{1,4})(?:\)?[\s#]*?\[#?\d+\])?(?:[\s#]*?and[\s#]*?(\d+))?",
    # --- Diffie Helman (CVL) ((cert #)) ---
    r"Diffie[-– ]*Hellman[,\s(\[]*?(?:CVL|\s)*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?[\s#]*?(\d{1,4})",
    # --- DRBG (bits) (method) (cert #) ---
    r"DRBG[ –-]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{1,4})",
    # --- DES (bits) (method) (cert #)
    r"DES[ –-]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT|CBC|(?:\d(?: and \d)? keying options?))*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)*?[\s#]*?)?[\s#]*?(\d{1,4})(?:[\s#]*?and[\s#]*?(\d+))?",
    # --- DSA (bits) (method) (cert #)
    r"DSA[ –-]*((?:;|\/|160|224|256|384|512)?(?: |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{1,4})",
    # --- platforms (#)+ - this is used in modification history ---
    r"[Pp]latforms? #\d+(?:#\d+|,| |-|and)*[^\n]*",
    # --- CVL (#) ---
    r"CVL[\s#]*?(\d{1,4})",
    # --- PAA (#) ---
    r"PAA[: #]*?\d{1,4}",
    # --- (#) Type ---
    r"(?:#|cert\.?|sample|Cert\.?|Certificate)[\s#]*?(\d+)?\s*?(?:AES|SHS|SHA|RSA|HMAC|Diffie-Hellman|DRBG|DES|CVL)",
    # --- PKCS (#) ---
    r"PKCS[\s]?#?\d+",
    r"PKSC[\s]?#?\d+",  # typo, #625
    # --- # C and # A (just in case) ---
    r"#\s+?[Cc]\d+",
    r"#\s+?[Aa]\d+",
]

rules_fips_to_remove = [
    # --- random words found ---
    r"[Ss]lot #\d",  # a card slot, #2069
    r"[Ss]eals? ?\(?#\d - #\d",  # #1232
    r"\[#\d*\]",  # some certs use this as references
    r"CSP ?#\d",  # #2795
    r"[Pp]ower [Ss]upply #\d",  # #604
    r"TEL #\d and #\d",  # #3337
    r"#\d+ - #\d+",  # labels, seals... #1232
    r"#\d+‐#?\d+",  # labels, seals... #3530
    r"#\d+ to #?\d+",  # labels, seals... #3058
    r"see #\d+",  # labels, seals... #3058
    r"#\d+, ?#\d+",
    r"#?\d+ and #?\d+",
    r"label \(#\d+\)",
    r"[Ll]abel #\d+",
    r"\(#\d\)",
    r"IETF[25\s]*RFC[26\s]*#\d+",  # #3425
    r"Document # 540-105000-A1",
    r"Certificate #2287-1 from EMCE Engineering",  # ???
    r"[sS]cenarios?\s?#\d+",  # 3789
    r"#\d+\s?\(\S\)",  # 2159
]

rules_fips_cert = [
    #     r"(?:#\s?|Cert\.?[^. ]*?\s?)(?P<id>\d{4})",
    #     r"(?:#\s?|Cert\.?[^. ]*?\s?)(?P<id>\d{3})",
    #     r"(?:#\s?|Cert\.?[^. ]*?\s?)(?P<id>\d{2})",
    #     r"(?:#\s?|Cert\.?[^. ]*?\s?)(?P<id>\d{1})
    r"(?:#[^\S\r\n]?|Cert\.?(?!.\s)[^\S\r\n]?|Certificate[^\S\r\n]?)(?P<id>\d{1,4})(?!\d)",
]

#  rule still too "general"
rules_fips_security_level = [r"[lL]evel (\d)"]

rules_fips_htmls = [
    r"module-name\">\s*(?P<fips_module_name>[^<]*)",
    r"module-standard\">\s*(?P<fips_standard>[^<]*)",
    r"Status[\s\S]*?\">\s*(?P<fips_status>[^<]*)",
    r"Sunset Date[\s\S]*?\">\s*(?P<fips_date_sunset>[^<]*)",
    r"Validation Dates[\s\S]*?\">\s*(?P<fips_date_validation>[^<]*)",
    r"Overall Level[\s\S]*?\">\s*(?P<fips_level>[^<]*)",
    r"Caveat[\s\S]*?\">\s*(?P<fips_caveat>[^<]*)",
    r"Security Level Exceptions[\s\S]*?\">\s*(?P<fips_exceptions><ul.*</ul>)",
    r"Module Type[\s\S]*?\">\s*(?P<fips_type>[^<]*)",
    r"Embodiment[\s\S]*?\">\s*(?P<fips_embodiment>[^<]*)",
    r"Tested Configuration[\s\S]*?\">\s*(?P<fips_tested_conf><ul.*</ul>)",
    r"FIPS Algorithms[\s\S]*?\">\s*(?P<fips_algorithms><tbody>[\s\S]*</tbody>)",
    r"Allowed Algorithms[\s\S]*?\">\s*(?P<fips_allowed_algorithms>[^<]*)",
    r"Software Versions[\s\S]*?\">\s*(?P<fips_software>[^<]*)",
    r"Product URL[\s\S]*?\">\s*<a href=\"(?P<fips_url>.*)\"",
    r"Vendor<\/h4>[\s\S]*?href=\".*?\">(?P<fips_vendor>.*?)<\/a>",
]


def _load():
    script_dir = Path(__file__).parent
    filepath = script_dir / "rules.yaml"
    with Path(filepath).open("r") as file:
        loaded = yaml.load(file, Loader=yaml.FullLoader)
    return loaded


def _process(obj, add_sep=True):
    if isinstance(obj, dict):
        return {k: _process(v, add_sep=add_sep) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [re.compile(rule + REGEXEC_SEP if add_sep else rule) for rule in obj]


rules = _load()

cc_rules = {}
for rule_group in rules["cc_rules"]:
    cc_rules[rule_group] = _process(rules[rule_group])

fips_rules = {}
for rule_group in rules["fips_rules"]:
    fips_rules[rule_group] = _process(rules[rule_group], False)
