from __future__ import annotations

import logging
import os
import re
from collections import Counter
from enum import Enum
from pathlib import Path
from typing import Any

import numpy as np

from sec_certs import constants
from sec_certs.cert_rules import REGEXEC_SEP, cc_rules
from sec_certs.constants import FILE_ERRORS_STRATEGY, LINE_SEPARATOR, MAX_ALLOWED_MATCH_LENGTH

logger = logging.getLogger(__name__)


def search_only_headers_anssi(filepath: Path):  # noqa: C901
    # TODO: Please, refactor me. I reallyyyyyyyyyyyyy need it!!!!!!
    class HEADER_TYPE(Enum):
        HEADER_FULL = 1
        HEADER_MISSING_CERT_ITEM_VERSION = 2
        HEADER_MISSING_PROTECTION_PROFILES = 3
        HEADER_DUPLICITIES = 4

    rules_certificate_preface = [
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeurs(.+)Centre d'évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit(.+)()Conformité à un profil de protection(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeur (.+)Centre d'évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom des produits(.+)Référence/version des produits(.+)Conformité à un profil de protection(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeur\\(s\\)(.+)Centre d'évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom des produits(.+)Référence/version des produits(.+)Conformité à un profil de protection(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeur (.+)Centre d'évaluation(.+)Accords de reconnaissance",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profils de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur\\(s\\)(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur\\(s\\)(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur (.+)Centre d’évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à des profils de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profils de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit \\(référence/version\\)(.+)Nom de la TOE \\(référence/version\\)(.+)Conformité à un profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeurs(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profil de protection(.+)Critères d’évaluation et version(.+)Niveau d’évaluation(.+)Développeur\\(s\\)(.+)Centre d’évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité à un profil de protection(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeur\\(s\\)(.+)Centre d'évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit \\(référence/version\\)(.+)Nom de la TOE \\(référence/version\\)(.+)Conformité à un profil de protection(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeurs(.+)Centre d'évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit(.+)Référence du produit(.+)Conformité à un profil de protection(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeurs(.+)Centre d'évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Conformité aux profils de protection(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeurs(.+)Centre d'évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur\\(s\\)(.+)dâ€™Ã©valuation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur (.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  des profils de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "RÃ©fÃ©rence du rapport de certification(.+)Nom du produit \\(rÃ©fÃ©rence/version\\)(.+)Nom de la TOE \\(rÃ©fÃ©rence/version\\)(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Certification Report(.+)Nom du produit(.+)Référence/version du produit(.*)Conformité à un profil de protection(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeurs(.+)Centre d'évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© aux profisl de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur (.+)Centres dâ€™Ã©valuation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)Version du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur (.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence/version du produit(.+)ConformitÃ© aux profils de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur\\(s\\)(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)Versions du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeur (.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "RÃ©fÃ©rence du rapport de certification(.+)Nom du produit(.+)RÃ©fÃ©rence du produit(.+)ConformitÃ© Ã  un profil de protection(.+)CritÃ¨res dâ€™Ã©valuation et version(.+)Niveau dâ€™Ã©valuation(.+)DÃ©veloppeurs(.+)Centre dâ€™Ã©valuation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer (.+)Evaluation facility(.+)Recognition arrangements",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer (.+)Evaluation facility(.+)Mutual Recognition Agreements",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Certification report reference(.+)Product name(.+)Product reference(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer\\(s\\)(.+)Evaluation facility(.+)Recognition arrangements",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Certification report reference(.+)Products names(.+)Products references(.+)protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Certification report reference(.+)Product name \\(reference / version\\)(.+)TOE name \\(reference / version\\)(.+)Protection profile conformity(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developers(.+)Evaluation facility(.+)Recognition arrangements",
        ),
        (
            HEADER_TYPE.HEADER_FULL,
            "Certification report reference(.+)TOE name(.+)Product's reference/ version(.+)TOE's reference/ version(.+)Conformité à un profil de protection(.+)Evaluation criteria and version(.+)Evaluation level(.+)Developer (.+)Evaluation facility(.+)Recognition arrangements",
        ),
        # corrupted text (duplicities)
        (
            HEADER_TYPE.HEADER_DUPLICITIES,
            "RÃ©fÃ©rencce du rapport de d certification n(.+)Nom du p produit(.+)RÃ©fÃ©rencce/version du produit(.+)ConformiitÃ© Ã  un profil de d protection(.+)CritÃ¨res d dâ€™Ã©valuation ett version(.+)Niveau dâ€™â€™Ã©valuation(.+)DÃ©velopp peurs(.+)Centre dâ€™â€™Ã©valuation(.+)Accords d de reconnaisssance applicab bles",
        ),
        # rules without product version
        (
            HEADER_TYPE.HEADER_MISSING_CERT_ITEM_VERSION,
            "Référence du rapport de certification(.+)Nom et version du produit(.+)Conformité à un profil de protection(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeurs(.+)Centre d'évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_MISSING_CERT_ITEM_VERSION,
            "Référence du rapport de certification(.+)Nom et version du produit(.+)Conformité à un profil de protection(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeur (.+)Centre d'évaluation(.+)Accords de reconnaissance applicables",
        ),
        (
            HEADER_TYPE.HEADER_MISSING_CERT_ITEM_VERSION,
            "Référence du rapport de certification(.+)Nom du produit(.+)Conformité à un profil de protection(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeurs(.+)Centre d'évaluation(.+)Accords de reconnaissance applicables",
        ),
        # rules without protection profile
        (
            HEADER_TYPE.HEADER_MISSING_PROTECTION_PROFILES,
            "Référence du rapport de certification(.+)Nom du produit(.+)Référence/version du produit(.+)Critères d'évaluation et version(.+)Niveau d'évaluation(.+)Développeurs(.+)Centre d'évaluation(.+)Accords de reconnaissance applicables",
        ),
    ]

    # statistics about rules success rate
    num_rules_hits = {}
    for rule in rules_certificate_preface:
        num_rules_hits[rule[1]] = 0

    items_found = {}  # type: ignore # noqa

    try:
        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_text_file(filepath)

        # for ANSII and DCSSI certificates, front page starts only on third page after 2 newpage signs
        pos = whole_text.find("")
        if pos != -1:
            pos = whole_text.find("", pos)
            if pos != -1:
                whole_text = whole_text[pos:]

        no_match_yet = True
        other_rule_already_match = False
        rule_index = -1
        for rule in rules_certificate_preface:
            rule_index += 1
            rule_and_sep = rule[1] + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                if no_match_yet:
                    items_found[constants.TAG_HEADER_MATCH_RULES] = []
                    no_match_yet = False

                # insert rule if at least one match for it was found
                if rule not in items_found[constants.TAG_HEADER_MATCH_RULES]:
                    items_found[constants.TAG_HEADER_MATCH_RULES].append(rule[1])

                if not other_rule_already_match:
                    other_rule_already_match = True
                else:
                    logger.warning(f"WARNING: multiple rules are matching same certification document: {filepath}")

                num_rules_hits[rule[1]] += 1  # add hit to this rule
                match_groups = m.groups()
                index_next_item = 0
                items_found[constants.TAG_CERT_ID] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                items_found[constants.TAG_CERT_ITEM] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                if rule[0] == HEADER_TYPE.HEADER_MISSING_CERT_ITEM_VERSION:
                    items_found[constants.TAG_CERT_ITEM_VERSION] = ""
                else:
                    items_found[constants.TAG_CERT_ITEM_VERSION] = normalize_match_string(match_groups[index_next_item])
                    index_next_item += 1

                if rule[0] == HEADER_TYPE.HEADER_MISSING_PROTECTION_PROFILES:
                    items_found[constants.TAG_REFERENCED_PROTECTION_PROFILES] = ""
                else:
                    items_found[constants.TAG_REFERENCED_PROTECTION_PROFILES] = normalize_match_string(
                        match_groups[index_next_item]
                    )
                    index_next_item += 1

                items_found[constants.TAG_CC_VERSION] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                items_found[constants.TAG_CC_SECURITY_LEVEL] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                items_found[constants.TAG_DEVELOPER] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1

                items_found[constants.TAG_CERT_LAB] = normalize_match_string(match_groups[index_next_item])
                index_next_item += 1
    except Exception as e:
        relative_filepath = "/".join(str(filepath).split("/")[-4:])
        error_msg = f"Failed to parse ANSSI frontpage headers from {relative_filepath}; {e}"
        logger.error(error_msg)
        return error_msg, None

    # if True:
    #     print('# hits for rule')
    #     sorted_rules = sorted(num_rules_hits.items(),
    #                           key=operator.itemgetter(1), reverse=True)
    #     used_rules = []
    #     for rule in sorted_rules:
    #         print('{:4d} : {}'.format(rule[1], rule[0]))
    #         if rule[1] > 0:
    #             used_rules.append(rule[0])

    return constants.RETURNCODE_OK, items_found


def search_only_headers_bsi(filepath: Path):  # noqa: C901
    # TODO: Please, refactor me. I reallyyyyyyyyyyyyy need it!!!!!!
    LINE_SEPARATOR_STRICT = " "
    NUM_LINES_TO_INVESTIGATE = 15
    rules_certificate_preface = [
        "(BSI-DSZ-CC-.+?) (?:for|For) (.+?) from (.*)",
        "(BSI-DSZ-CC-.+?) zu (.+?) der (.*)",
    ]

    items_found = {}  # type: ignore # noqa
    no_match_yet = True

    try:
        # Process front page with info: cert_id, certified_item and developer
        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_text_file(
            filepath, NUM_LINES_TO_INVESTIGATE, LINE_SEPARATOR_STRICT
        )

        for rule in rules_certificate_preface:
            rule_and_sep = rule + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                if no_match_yet:
                    items_found[constants.TAG_HEADER_MATCH_RULES] = []
                    no_match_yet = False

                # insert rule if at least one match for it was found
                if rule not in items_found[constants.TAG_HEADER_MATCH_RULES]:
                    items_found[constants.TAG_HEADER_MATCH_RULES].append(rule)

                match_groups = m.groups()
                cert_id = match_groups[0]
                certified_item = match_groups[1]
                developer = match_groups[2]

                FROM_KEYWORD_LIST = [" from ", " der "]
                for from_keyword in FROM_KEYWORD_LIST:
                    from_keyword_len = len(from_keyword)
                    if certified_item.find(from_keyword) != -1:
                        logger.warning(
                            f"string {from_keyword} detected in certified item - shall not be here, fixing..."
                        )
                        certified_item_first = certified_item[: certified_item.find(from_keyword)]
                        developer = certified_item[certified_item.find(from_keyword) + from_keyword_len :]
                        certified_item = certified_item_first
                        continue

                end_pos = developer.find("\f-")
                if end_pos == -1:
                    end_pos = developer.find("\fBSI")
                if end_pos == -1:
                    end_pos = developer.find("Bundesamt")
                if end_pos != -1:
                    developer = developer[:end_pos]

                items_found[constants.TAG_CERT_ID] = normalize_match_string(cert_id)
                items_found[constants.TAG_CERT_ITEM] = normalize_match_string(certified_item)
                items_found[constants.TAG_DEVELOPER] = normalize_match_string(developer)
                items_found[constants.TAG_CERT_LAB] = "BSI"

        # Process page with more detailed sample info
        # PP Conformance, Functionality, Assurance
        rules_certificate_third = ["PP Conformance: (.+)Functionality: (.+)Assurance: (.+)The IT Product identified"]

        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_text_file(filepath)

        for rule in rules_certificate_third:
            rule_and_sep = rule + REGEXEC_SEP

            for m in re.finditer(rule_and_sep, whole_text):
                # check if previous rules had at least one match
                if constants.TAG_CERT_ID not in items_found:
                    logger.error(f"ERROR: front page not found for file: {filepath}")

                match_groups = m.groups()
                ref_protection_profiles = match_groups[0]
                cc_version = match_groups[1]
                cc_security_level = match_groups[2]

                items_found[constants.TAG_REFERENCED_PROTECTION_PROFILES] = normalize_match_string(
                    ref_protection_profiles
                )
                items_found[constants.TAG_CC_VERSION] = normalize_match_string(cc_version)
                items_found[constants.TAG_CC_SECURITY_LEVEL] = normalize_match_string(cc_security_level)

        # print('\n*** Certificates without detected preface:')
        # for file_name in files_without_match:
        #     print('No hits for {}'.format(file_name))
        # print('Total no hits files: {}'.format(len(files_without_match)))
        # print('\n**********************************')
    except Exception as e:
        relative_filepath = "/".join(str(filepath).split("/")[-4:])
        error_msg = f"Failed to parse BSI headers from frontpage: {relative_filepath}; {e}"
        logger.error(error_msg)
        return error_msg, None

    return constants.RETURNCODE_OK, items_found


def search_only_headers_nscib(filepath: Path):  # noqa: C901
    # TODO: Please, refactor me. I reallyyyyyyyyyyyyy need it!!!!!!
    LINE_SEPARATOR_STRICT = " "
    NUM_LINES_TO_INVESTIGATE = 60
    items_found: dict[str, str] = {}

    try:
        # Process front page with info: cert_id, certified_item and developer
        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_text_file(
            filepath, NUM_LINES_TO_INVESTIGATE, LINE_SEPARATOR_STRICT
        )

        certified_item = ""
        developer = ""
        cert_lab = ""
        cert_id = ""

        lines = whole_text_with_newlines.splitlines()
        no_match_yet = True
        item_offset = -1

        for line_index in range(0, len(lines)):
            line = lines[line_index]

            if "Certification Report" in line:
                item_offset = line_index + 1
            if "Assurance Continuity Maintenance Report" in line:
                item_offset = line_index + 1

            SPONSORDEVELOPER_STR = "Sponsor and developer:"

            if SPONSORDEVELOPER_STR in line:
                if no_match_yet:
                    items_found = {}
                    no_match_yet = False

                # all lines above till 'Certification Report' or 'Assurance Continuity Maintenance Report'
                certified_item = ""
                for name_index in range(item_offset, line_index):
                    certified_item += lines[name_index] + " "
                developer = line[line.find(SPONSORDEVELOPER_STR) + len(SPONSORDEVELOPER_STR) :]

            SPONSOR_STR = "Sponsor:"

            if SPONSOR_STR in line:
                if no_match_yet:
                    items_found = {}
                    no_match_yet = False

                # all lines above till 'Certification Report' or 'Assurance Continuity Maintenance Report'
                certified_item = ""
                for name_index in range(item_offset, line_index):
                    certified_item += lines[name_index] + " "

            DEVELOPER_STR = "Developer:"
            if DEVELOPER_STR in line:
                developer = line[line.find(DEVELOPER_STR) + len(DEVELOPER_STR) :]

            CERTLAB_STR = "Evaluation facility:"
            if CERTLAB_STR in line:
                cert_lab = line[line.find(CERTLAB_STR) + len(CERTLAB_STR) :]

            REPORTNUM_STR = "Report number:"
            if REPORTNUM_STR in line:
                cert_id = line[line.find(REPORTNUM_STR) + len(REPORTNUM_STR) :]

        if not no_match_yet:
            items_found[constants.TAG_CERT_ID] = normalize_match_string(cert_id)
            items_found[constants.TAG_CERT_ITEM] = normalize_match_string(certified_item)
            items_found[constants.TAG_DEVELOPER] = normalize_match_string(developer)
            items_found[constants.TAG_CERT_LAB] = cert_lab

    except Exception as e:
        error_msg = f"Failed to parse NSCIB headers from frontpage: {filepath}; {e}"
        logger.error(error_msg)
        return error_msg, None

    return constants.RETURNCODE_OK, items_found


def search_only_headers_niap(filepath: Path):
    # TODO: Please, refactor me. I reallyyyyyyyyyyyyy need it!!!!!!
    LINE_SEPARATOR_STRICT = " "
    NUM_LINES_TO_INVESTIGATE = 15
    items_found: dict[str, str] = {}

    try:
        # Process front page with info: cert_id, certified_item and developer
        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_text_file(
            filepath, NUM_LINES_TO_INVESTIGATE, LINE_SEPARATOR_STRICT
        )

        certified_item = ""
        cert_id = ""

        lines = whole_text_with_newlines.splitlines()
        no_match_yet = True
        item_offset = -1

        for line_index in range(0, len(lines)):
            line = lines[line_index]

            if "Validation Report" in line:
                item_offset = line_index + 1

            REPORTNUM_STR = "Report Number:"
            if REPORTNUM_STR in line:
                if no_match_yet:
                    items_found = {}
                    no_match_yet = False

                # all lines above till 'Certification Report' or 'Assurance Continuity Maintenance Report'
                certified_item = ""
                for name_index in range(item_offset, line_index):
                    certified_item += lines[name_index] + " "
                cert_id = line[line.find(REPORTNUM_STR) + len(REPORTNUM_STR) :]
                break

        if not no_match_yet:
            items_found[constants.TAG_CERT_ID] = normalize_match_string(cert_id)
            items_found[constants.TAG_CERT_ITEM] = normalize_match_string(certified_item)
            items_found[constants.TAG_CERT_LAB] = "US NIAP"

    except Exception as e:
        error_msg = f"Failed to parse NIAP headers from frontpage: {filepath}; {e}"
        logger.error(error_msg)
        return error_msg, None

    return constants.RETURNCODE_OK, items_found


def search_only_headers_canada(filepath: Path):  # noqa: C901
    # TODO: Please, refactor me. I reallyyyyyyyyyyyyy need it!!!!!!
    LINE_SEPARATOR_STRICT = " "
    NUM_LINES_TO_INVESTIGATE = 20
    items_found: dict[str, str] = {}
    try:
        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_text_file(
            filepath, NUM_LINES_TO_INVESTIGATE, LINE_SEPARATOR_STRICT
        )

        cert_id = ""

        lines = whole_text_with_newlines.splitlines()
        no_match_yet = True
        for line_index in range(0, len(lines)):
            line = lines[line_index]
            if "Government of Canada, Communications Security Establishment" in line:
                REPORTNUM_STR1 = "Evaluation number:"
                REPORTNUM_STR2 = "Document number:"
                matched_number_str = ""
                line_certid = lines[line_index + 1]
                if line_certid.startswith(REPORTNUM_STR1):
                    matched_number_str = REPORTNUM_STR1
                if line_certid.startswith(REPORTNUM_STR2):
                    matched_number_str = REPORTNUM_STR2
                if matched_number_str != "":
                    if no_match_yet:
                        items_found = {}
                        no_match_yet = False

                    cert_id = line_certid[line_certid.find(matched_number_str) + len(matched_number_str) :]
                    break

            if (
                "Government of Canada. This document is the property of the Government of Canada. It shall not be altered,"
                in line
            ):
                REPORTNUM_STR = "Evaluation number:"
                for offset in range(1, 20):
                    line_certid = lines[line_index + offset]
                    if "UNCLASSIFIED" in line_certid:
                        if no_match_yet:
                            items_found = {}
                            no_match_yet = False
                        line_certid = lines[line_index + offset - 4]
                        cert_id = line_certid[line_certid.find(REPORTNUM_STR) + len(REPORTNUM_STR) :]
                        break
                if not no_match_yet:
                    break

            if (
                "UNCLASSIFIED / NON CLASSIFIÉ" in line
                and "COMMON CRITERIA CERTIFICATION REPORT" in lines[line_index + 2]
            ):
                line_certid = lines[line_index + 1]
                if no_match_yet:
                    items_found = {}
                    no_match_yet = False
                cert_id = line_certid
                break

        if not no_match_yet and cert_id:
            items_found[constants.TAG_CERT_ID] = normalize_match_string(cert_id)
            items_found[constants.TAG_CERT_LAB] = "CANADA"

    except Exception as e:
        error_msg = f"Failed to parse Canada headers from frontpage: {filepath}; {e}"
        logger.error(error_msg)
        return error_msg, None

    return constants.RETURNCODE_OK, items_found


def flatten_matches(dct: dict) -> dict:
    """
    Function to flatten dictionary of matches.

    Turns
    ```
        {"a": {"cc": 3}, "b": {}, "d": {"dd": 4, "cc": 2}}
    ```
    into
    ```
        {"cc": 5, "dd": 4}
    ```

    :param dct: Dictionary to flatten
    :return: Flattened dictionary
    """
    result: Counter[Any] = Counter()
    for key, value in dct.items():
        if isinstance(value, dict):
            result.update(flatten_matches(value))
        else:
            result[key] = value
    return dict(result)


def prune_matches(dct: dict) -> dict:
    """
    Prune a dictionary of matches.

    Turns
    ```
        {"a": {"cc": 3}, "b": {"aa": {}, "bb": {}}, "d": {"dd": 4, "cc": 2}}
    ```
    into
    ```
        {"a": {"cc": 3}, "b": {}, "d": {"dd": 4, "cc": 2}}
    ```

    :param dct: The dictionary of matches.
    :return: The pruned dictionary.
    """

    def walk(obj, depth):
        if isinstance(obj, dict):
            if not obj:
                return None
            res = {}
            for k, v in obj.items():
                r = walk(v, depth + 1)
                if r is not None:
                    res[k] = r
            return res if res or depth == 1 else None
        else:
            return obj

    return walk(dct, 0)


def extract_keywords(filepath: Path, search_rules) -> dict[str, dict[str, int]] | None:
    """
    Extract keywords from filepath using the search rules.

    :param filepath:
    :param search_rules:
    :return:
    """

    try:
        whole_text, whole_text_with_newlines, was_unicode_decode_error = load_text_file(filepath, -1, LINE_SEPARATOR)

        def extract(rules):
            if isinstance(rules, dict):
                return {k: extract(v) for k, v in rules.items()}
            if isinstance(rules, list):
                matches = [extract(rule) for rule in rules]
                c = Counter()
                for match_list in matches:
                    c += Counter(match_list)
                return dict(c)
            if isinstance(rules, re.Pattern):
                rule = rules
                matches = []
                for match in rule.finditer(whole_text):
                    match = match.group("match")
                    match = normalize_match_string(match)

                    match_len = len(match)
                    if match_len > MAX_ALLOWED_MATCH_LENGTH:
                        logger.warning(f"Excessive match with length of {match_len} detected for rule {rule.pattern}")
                    matches.append(match)
                return matches

        result = extract(search_rules)
        return prune_matches(result)
    except Exception as e:
        relative_filepath = "/".join(str(filepath).split("/")[-4:])
        error_msg = f"Failed to parse keywords from: {relative_filepath}; {e}"
        logger.error(error_msg)
        return None


def normalize_match_string(match: str) -> str:
    match = match.strip().strip("[];.”\"':)(,").rstrip(os.sep).replace("  ", " ")
    return "".join(filter(str.isprintable, match))


def load_text_file(
    file_name: str | Path, limit_max_lines: int = -1, line_separator: str = LINE_SEPARATOR
) -> tuple[str, str, bool]:
    """
    Load the text contents of a file at `file_name`, upto `limit_max_lines` of lines, replace
    newlines in the text with `line_separator`.

    :param file_name: The file_name to load.
    :param limit_max_lines: The limit on number of lines to return.
    :param line_separator: The string to replace newlines with.
    :return: A tuple of three elements (the text with replaced newlines, the text and a boolean whether a unicode
             decoding error happened).
    """
    lines = []
    was_unicode_decode_error = False
    with Path(file_name).open("r", errors=FILE_ERRORS_STRATEGY) as f:
        try:
            lines = f.readlines()
        except UnicodeDecodeError:
            was_unicode_decode_error = True
            logger.warning("UnicodeDecodeError, opening as utf8")

    if was_unicode_decode_error:
        with Path(file_name).open("r", encoding="utf8", errors=FILE_ERRORS_STRATEGY) as f2:
            # coding failure, try line by line
            line = " "
            while line:
                try:
                    line = f2.readline()
                    lines.append(line)
                except UnicodeDecodeError:
                    # ignore error
                    continue

    whole_text = ""
    whole_text_with_newlines = ""
    lines_included = 0
    for line in lines:
        if limit_max_lines != -1 and lines_included >= limit_max_lines:
            break

        whole_text_with_newlines += line
        line = line.replace("\n", "")
        whole_text += line
        whole_text += line_separator
        lines_included += 1

    return whole_text, whole_text_with_newlines, was_unicode_decode_error


def rules_get_subset(desired_path: str) -> dict:
    """























    Recursively applies cc_certs.get(key) on tokens from desired_path,
    returns the keys of the inner-most layer.
    """
    dct = cc_rules
    for token in desired_path.split("."):
        dct = dct[token]
    return dct


def extract_key_paths(dct: dict, current_path: str) -> list[str]:
    """
    Given subset of cc_rules dictionary, will compute full paths to all leafs
    in the dictionaries, s.t. the final value of each path is a list of regex
    matches in the keywords dictionary.
    """
    paths = []
    for key in dct:
        if isinstance(dct[key], dict):
            paths.extend(extract_key_paths(dct[key], current_path + "." + key))
        elif isinstance(dct[key], list):
            paths.append(current_path + "." + key)
    return paths


def get_sum_of_values_from_dict_path(dct: dict | None, path: str, default: float = np.nan) -> float:
    """
    Given dictionary and path, will compute sum of occurences of values in the inner-most layer
    of that path. If the key is missing from dict, return default value.
    """
    if not dct:
        return np.nan

    res = dct

    try:
        for token in path.split("."):
            res = res[token]
    except KeyError:
        return default

    return sum(res.values())


def get_sums_for_rules_subset(dct: dict | None, path: str) -> dict[str, float]:
    """
    Given path to search in cc_rules (e.g., "symmetric_crypto"),
    will get the finest resolution and count occurences of the keys in the
    examined dictionary.
    """
    cc_rules_subset_to_search = rules_get_subset(path)
    paths_to_search = extract_key_paths(cc_rules_subset_to_search, path)
    return {x: get_sum_of_values_from_dict_path(dct, x, np.nan) for x in paths_to_search}
