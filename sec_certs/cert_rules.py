import copy
import re
from typing import Dict, List, Pattern, Set, Tuple

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

rules_cert_id = [
    "BSI-DSZ-CC-[0-9]+?-[0-9]+",  # German BSI
    "BSI-DSZ-CC-[0-9]+?-(?:V|v)[0-9]+-[0-9]+",  # German BSI
    "BSI-DSZ-CC-[0-9]+?-(?:V|v)[0-9]+",  # German BSI
    "BSI-DSZ-CC-[0-9]+-(?:V|v)[0-9]+(-[0-9][0-9][0-9][0-9])*",  # German BSI (number + version + year or without year)
    "BSI-DSZ-CC-[0-9]+-[0-9][0-9][0-9][0-9]",  # German BSI (number + year, no version)
    "BSI-DSZ-CC-[0-9]+-(?:V|v)[0-9]+(?!-)",  # German BSI (number + version but no year => no - after version)
    # 'CC-Zert-.+?',
    "ANSSI(?:-|-CC-)[0-9]+?/[0-9]+(v[1-9])?",  # French
    "ANSS[Ii]-CC-[0-9][0-9][0-9][0-9][/-_][0-9][0-9]+(?!-M|-S)",  # French (/two or more digits then NOT -M or -S)
    "ANSS[Ii]-CC-[0-9][0-9][0-9][0-9][/-_][0-9]+[_/-]M[0-9]+",  # French, maintenance report (ANSSI-CC-2014_46_M01)
    "ANSS[Ii]-CC-[0-9][0-9][0-9][0-9][/-_][0-9]+[_/-]S[0-9]+",  # French, surveillance report (ANSSI-CC-2012/70-S01)
    # 'ANSSI-CC-CER-F-.+?', # French
    "DCSSI-[0-9]+/[0-9]+",  # French (DCSSI-2009/07)
    "Certification Report [0-9]+/[0-9]+",  # French or Australia
    "Rapport de certification [0-9]+/[0-9]+",  # French
    "NSCIB-CC-[0-9][0-9][0-9][0-9].+?",  # Netherlands
    "NSCIB-CC-[0-9][0-9][0-9][0-9][0-9]*-CR",  # Netherlands
    "NSCIB-CC-[0-9][0-9]-[0-9]+?-CR[0-9]+?",  # Netherlands
    "NSCIB-CC-[0-9][0-9]-[0-9]+(-CR[0-9]+)*",  # Netherlands (old number NSCIB-CC-05-6609 or NSCIB-CC-05-6609-CR)
    "NSCIB-CC-[0-9]+-CR[0-9]*",  # Netherlands (new number NSCIB-CC-111441-CR NSCIB-CC-111441-CR1)
    "NSCIB-CC-[0-9]+-MA[0-9]*",  # Netherlands (new number NSCIB-CC-222073-MA NSCIB-CC-200716-MA2)
    "NSCIB-CC-[0-9][0-9]-[0-9]+",  # Netherlands   (old number NSCIB-CC-05-6609)
    "NSCIB-CC-[0-9][0-9]-[0-9]+-CR[0-9]+",  # Netherlands (NSCIB-CC-year2digits-number-CR)
    "SERTIT-[0-9]+",  # Norway
    "CCEVS-VR-(?:|VID)[0-9]+-[0-9]+[a-z]?",  # US NSA (CCEVS-VR-10884-2018 CCEVS-VR-VID10877-2018)
    # '[0-9][0-9\-]+?-CR', # Canada
    "CRP[0-9]+",  # UK CESG
    "CRP[0-9][0-9][0-9][0-9]*?",  # UK CESG
    "CERTIFICATION REPORT No. P[0-9]+",  # UK CESG
    "20[0-9][0-9]-[0-9]+-INF-[0-9]+",  # Spain
    "20[0-9][0-9]-[0-9]+-INF-[0-9]+(.(?:V|v)[0-9]+)*",  # Spain (2006-4-INF-98 v2 or (2006-4-INF-98-v2))
    "KECS-CR-[0-9]+-[0-9]+",  # Korea KECS-CR-20-61
    "KECS-ISIS-[0-9]+?-[0-9][0-9][0-9][0-9]",  # Korea
    "KECS-(?:ISIS|NISS|CISS)-[0-9]+-[0-9][0-9][0-9][0-9]",  # Korea
    "CRP-C[0-9]+?-[0-9]+?",  # Japan
    "(?:CRP|ACR)-C[0-9]+-[0-9]+",  # Japan (CRP-C0595-01 ACR-C0417-03)
    "JISEC-CC-CRP-C[0-9]+-[0-9]+-[0-9]+",  # Japan (JISEC-CC-CRP-C0689-01-2020)
    "Certification No. C[0-9]+" "ISCB-[0-9]+?-RPT-[0-9]+?",  # Japan (Certification No. C0090)  # Malaysia
    # Malaysia (ISCB-3-RPT-C092-CR-v1, ISCB-3-RPT-C068-CR-1-v1)
    "ISCB-[0-9]+-(?:RPT|FRM)-[CM][0-9]+[A-Z]?-(?:CR|AMR)(?:-[0-9]|)-[vV][0-9][a-z]?" "OCSI/CERT/.+?",  # Italia
    r"OCSI/CERT/.+?/20[0-9]+(?:\w|/RC)",  # Italia  (OCSI/CERT/ATS/01/2018/RC)
    "[0-9\\.]+?/TSE-CCCS-[0-9]+",  # Turkis CCCS (21.0.0sc/TSE-CCCS-75)
    "CSEC[0-9]+",  # Sweden (CSEC2019015)
    # India (IC3S/DEL01/VALIANT/EAL1/0317/0007/CR  STQC/CC/14-15/12/ETR/0017 IC3S/MUM01/CISCO/cPP/0119/0016/CR)
    # will miss STQC/CC/14-15/12/ETR/0017
    "(?:IC3S|STQC/CC)/[^ ]+?/CR ",  # must end with CR, no space inside
    "CSA_CC_[0-9]+",  # Singapure (CSA_CC_19001)
    "[0-9][0-9][0-9]-[47]-[0-9][0-9][0-9](-CR)*",  # Canada xxx-{47}-xxx (383-4-438, 383-4-82-CR)
    "[0-9][0-9][0-9](?: |-)(?:EWA|LSS)(?: |-)20[0-9][0-9]",  # Canada (522-EWA-2020, 524 LSS 2020)
    # Canada filename with space (518-LSS%20CR%20v1.0)
    r"[0-9][0-9][0-9](?:%20|-)(?:EWA|LSS|CCS)(?:%20|-)(?:20[0-9][0-9]%20|)CR%20v[0-9]\.[0-9]",
    # Australia (EFS-T048 ETR 1.0, EFS-T056-ETR 1.0, DXC-EFC-T092-ETR 1.0)
    "(?:EFS|EFT|DXC-EFC)-T[0-9]+(?: |-)ETR [0-9]+.[0-9]+",
]

rules_vendor = [
    "NXP",
    "Infineon",
    "Samsung",
    "(?:STMicroelectronics|STM)",
    "Feitian",
    "Gemalto",
    "Gemplus",
    "Axalto",
    "(?:Oberthur|OBERTHUR)",
    "(?:Idemia|IDEMIA)",
    r"(?:G\&D|G\+D|Giesecke\+Devrient|Giesecke \& Devrient)",
    "Philips",
    "Sagem",
    "Qualcomm",
    "Broadcom",
    "Huawei",
]

# From: https://www.commoncriteriaportal.org/labs/
rules_eval_facilities = [
    "(Serma Technologies|SERMA|Serma Safety & Security)",
    "(THALES - CEACI|THALES/CNES)",
    "Riscure",
    "Bright[sS]ight",
    "Applus Laboratories",
    "SGS",
    "SGS Bright[sS]ight",
    "(tuvit|TÜViT|TUViT|TÜV Informationstechnik|TUV Informationstechnik)",
    "CESTI",
    "DXC Technology",
    "Teron Labs",
    "(EWA|EWA-Canada)",
    "Lightship Security",
    "AMOSSYS",
    "(CEA - LETI|CEA/LETI|CEA-LETI)",
    "OPPIDA",
    "Trusted Labs",
    "atsec",
    "Deutsche Telekom Security",
    "(Deutsches Forschungszentrum für künstliche Intelligenz|dfki|DFKI)",
    "MTG AG",
    "secuvera",
    "SRC Security Research & Consulting",
    "Acucert Labs",
    "Common Criteria Test Laboratory,? ERTL",
    "Common Criteria Test Laboratory,? ETDC",
    "CCLab Software Laboratory",
    "Deeplab",
    "IMQ/LPS",
    "LVS Leonardo",
    "LVS Technis Blu",
    "ECSEC Laboratory",
    "Information Technology Security Center",
    "Acumen Security",
    "Booz Allen Hamilton",
    "Gossamer Security",
    "Leidos",
    "UL Verification Services",
    "BEAM Teknoloji",
    "Certby Lab",
    "DEKRA Testing and Certification",
    "STM ITSEF",
    "TÜBİTAK BİLGEM",
    "Leidos Common Criteria Testing Laboratory",
    "Combitech AB",
    "Intertek",
    "Clover Technologies",
    "LAYAKK SEGURIDAD INFORMATICA",
    "An Security",
    "T-Systems International",
    "KISA",
    "KOIST",
    "KSEL",
    "KOSYAS",
    "KTR",
    "KTC",
    "TTA",
    "Advanced Data Security",
    "Nemko System Sikkerhet",
    "Norconsult AS",
    "Secura",
    "UL",
    "BAE Applied Intelligence",
]

rules_protection_profiles = [
    "BSI-(?:CC[-_]|)PP[-_]*.+?",
    "PP-SSCD.+?",
    "PP_DBMS_.+?"
    #  'Protection Profile',
    # 'CCMB-20.+?',
    "BSI-CCPP-.+?",
    "ANSSI-CC-PP.+?",
    "WBIS_V[0-9]\\.[0-9]",
    "EHCT_V.+?",
]

rules_technical_reports = [
    "BSI[ ]*TR-[0-9]+?(?:-[0-9]+?|)",
    "BSI [0-9]+?",  # German BSI document containing list of issued certificates in some period
]

rules_device_id = [
    "G87-.+?",
    "ATMEL AT.+?",
    "STM32[FGLHW][0-7][0-9]{1,2}[FGKTSCRVZI][468BCDEFGHI][PHUTY][67]",
    "SLE[0-9]{2}[A-Z]{3}[0-9]{1-4}[A-Z]{1-3}",
]

rules_tee = [
    "TEE",
    "(ARM )?TrustZone",
    "(ARM )?(Realm Management Extension|Confidential Compute Architecture)",
    "(Intel )?SGX",
    "Cloud Link TEE",
    "iOS Secure Enclave",
    "iTrustee",
    "Trusty",
    "OPTEE",
    "QTEE",
    "TEEgris",
    "T6",
    "Kinibi",
    "SW TEE",
    "WatchTrust",
    "(AMD )?(PSP|Platform Security Processor)",
    "(AMD )?(SEV|Secure Encrypted Virtualization)",
    "(IBM )?(SSC|Secure Service Container)",
    "(IBM )?(SE|Secure Execution)",
]

rules_os = ["STARCOS(?: [0-9\\.]+?|)", "JCOP[ ]*[0-9]"]

rules_standard_id = [
    "FIPS ?(?:PUB )?[0-9]+-[0-9]+?",
    "FIPS ?(?:PUB )?[0-9]+?",
    "NIST SP [0-9]+-[0-9]+?[a-zA-Z]?",
    "PKCS[ #]*[1-9]+",
    "TLS[ ]*v[0-9\\.]+",
    "TLS[ ]*v[0-9\\.]+",
    "BSI-AIS[ ]*[0-9]+?",
    "AIS[ ]*[0-9]+?",
    "RFC[ ]*[0-9]+?",
    "ISO/IEC[ ]*[0-9]+[-]*[0-9]*",
    "ISO/IEC[ ]*[0-9]+:[ 0-9]+",
    "ISO/IEC[ ]*[0-9]+",
    "ICAO(?:-SAC|)",
    "[Xx]\\.509",
    "RFC [0-9]+",
    "(?:SCP|scp)[ ']*[0-9][0-9]",
    "CC[I]*MB-20[0-9]+?-[0-9]+?-[0-9]+?",  # Common Criteria methodology
    "CCIMB-9[0-9]-[0-9]+?",  # Common Criteria methodology old
]

rules_security_level = [
    "EAL[ ]*[0-9+]+?",
    "EAL[ ]*[0-9] augmented+?",
    "ITSEC[ ]*E[1-9]*.+?",
]

security_level_csv_scan = r"EAL[1-7]\+?"

rules_security_assurance_components = [
    r"ACE(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"ACM(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"ACO(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"ADO(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"ADV(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"AGD(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"ALC(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"ATE(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"AVA(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"AMA(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"APE(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"ASE(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
]

rules_security_functional_components = [
    r"FAU(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"FCO(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"FCS(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"FDP(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"FIA(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"FMT(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"FPR(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"FPT(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"FRU(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"FTA(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
    r"FTP(?:_[A-Z]{3,4}){1,2}(?:\.[0-9]|\.[0-9]\.[0-9]|)",
]

rules_cc_claims = [
    r"D\.[\._\-A-Z]+?",  # user Data
    r"O\.[\._\-A-Z]+?",  # Objectives
    r"T\.[\._\-A-Z]+?",  # Threats
    r"A\.[\._\-A-Z]+?",  # Assumptions
    r"R\.[\._\-A-Z]+?",  # Requirements
    r"OT\.[\._\-A-Z]+?",  # security objectives
    r"OP\.[\._\-A-Z]+?",  # OPerations
    r"OE\.[\._\-A-Z]+?",  # Objectives for the Environment
    r"SA\.[\._\-A-Z]+?",  # Security Aspects
    r"OSP\.[\._\-A-Z]+?",  # Organisational Security Policy
]

rules_javacard = [
    # '(?:Java Card|JavaCard)',
    # '(?:Global Platform|GlobalPlatform)',
    r"(?:Java Card|JavaCard) [2-3]\.[0-9](?:\.[0-9]|)",
    r"JC[2-3]\.[0-9](?:\.[0-9]|)",
    r"(?:Java Card|JavaCard) \(version [2-3]\.[0-9](?:\.[0-9]|)\)",
    r"(?:Global Platform|GlobalPlatform) [2-3]\.[0-9]\.[0-9]",
    r"(?:Global Platform|GlobalPlatform) \(version [2-3]\.[0-9]\.[0-9]\)",
]

rules_javacard_api_consts = [
    # javacard API constants
    r"ALG_(?:PSEUDO_RANDOM|SECURE_RANDOM|TRNG|ALG_PRESEEDED_DRBG|FAST|KEYGENERATION)",
    r"ALG_DES_[A-Z_0-9]+",
    r"ALG_RSA_[A-Z_0-9]+",
    r"ALG_DSA_[A-Z_0-9]+",
    r"ALG_ECDSA_[A-Z_0-9]+",
    r"ALG_AES_[A-Z_0-9]+",
    r"ALG_HMAC_[A-Z_0-9]+",
    r"ALG_KOREAN_[A-Z_0-9]+",
    r"ALG_EC_[A-Z_0-9]+?",  # may have false positives like XCP_CPB_ALG_EC_BPOOLCRV
    r"ALG_SHA_[A-Z_0-9]+",
    r"ALG_SHA3_[A-Z_0-9]+",
    r"ALG_MD[A-Z_0-9]+",
    r"ALG_RIPEMD[A-Z_0-9]+",
    r"ALG_ISO3309_[A-Z_0-9]+",
    r"ALG_XDH",
    r"ALG_SM2",
    r"ALG_SM3",
    r"ALG_NULL",
    r"ALG_TRNG",
    r"ALG_NULL",
    r"SIG_CIPHER_[A-Z_0-9]+",
    r"CIPHER_[A-Z_0-9]+",
    r"PAD_[A-Z_0-9]+",
    r"TYPE_[A-Z_0-9]+",
    r"LENGTH_[A-Z_0-9]+",
    r"OWNER_PIN[A-Z_0-9]*",
    # named curves
    r"BRAINPOOLP[A-Z_0-9]+(?:R|T)1",
    r"ED25519",
    r"ED448",
    r"FRP256V1",
    r"SECP[0-9]*R1",
    r"SM2",
    r"X25519",
    r"X448",
]

rules_javacard_packages = [
    # javacard packages
    r"java\.[a-z\.]+",
    r"javacard\.[a-z\.]+",
    r"javacardx\.[a-z\.]+",
    r"org\.[0-9a-z\.]+",
    r"uicc\.[a-z\.]+",
    r"com\.[0-9a-z\.]+",
    r"de\.bsi\.[a-z\.]+",
]

rules_symmetric_crypto = [
    # AES competition
    "AES-?(?:128|192|256|)",
    "Rijndael",
    "Twofish",
    "Serpent",
    "MARS",
    "HPC",
    "FROG",
    "CAST-?(?:128|160|192|224|256|5)",
    "RC[2456]",
    "CRYPTON",
    "DEAL",
    "E2",
    "LOKI97",
    "MAGENTA",
    "SAFER\\+",
    # DES related
    "[3T]?DE[SA]",
    "Lucifer",
    # djb
    "ChaCha20",
    "Poly1305",
    "Salsa20",
    # LWC
    "(ASCON|Ascon)",
    "Elephant",
    "GIFT(-COFB)?",
    "Grain128(-AEAD)?",
    "ISAP",
    "Photon-Beetle",
    "Romulus",
    "Sparkle",
    "TinyJambu",
    "Xoodyak",
    "Gimli",
    # Constructions
    "HMAC",
    "HMAC-SHA-(?:160|224|256|384|512)",
    "KMAC",
    # eSTREAM
    "HC-[0-9]{3}",
    "Rabbit",
    "SOSEMANUK",
    "MICKEY(-128)?",
    "Trivium",
    # CAESAR
    "ACORN",
    "AEGIS(-128)?",
    "Deoxys(-2)?",
    "COLM",
    # Misc
    "IDEA",
    "Blowfish",
    "Camellia",
    "CAST",
    "ARIA",
    "SM4",
    "GOST 28147-89",
    "Skipjack",
    "(Skinny|SKINNY)",
    "Kuznyechik",
]

rules_asymmetric_crypto = [
    "RSA[- ]*(?:512|768|1024|1280|1536|2048|3072|4096|8192)",
    "RSASSAPKCS1-[Vv]1_5",
    "ECDHE?",
    "ECDSA",
    "EdDSA",
    "ECC",
    "(Diffie-Hellman|DH|DHE)",
    "DSA",
    "BLS",
    "ECIES",
]

rules_pq_crypto = [
    "Classic[ -]McEliece",
    "(CRYSTALS-)?(Kyber|KYBER)",
    "NTRU",
    "SABER",
    "(CRYSTALS-)?(Dilithium|DILITHIUM)",
    "FALCON",
    "Rainbow",
    "BIKE",
    "Frodo(KEM)?",
    "HQC",
    "NTRU[ -]Prime",
    "SIKE",
    "GeMSS",
    "Picnic",
    "SPHINCS\\+",
]

rules_hashes = [
    # SHA-1
    "SHA-?1",
    # SHA-2
    "SHA-?(?:160|224|256|384|512)",
    # SHA-3
    "SHA-?3(-[0-9]{3})?",
    "Keccak",
    "SHAKE[0-9]{3}" "(Groestl|Grøstl)",
    "(Blake|BLAKE)[23][sbX]?",
    "JH",
    "Skein",
    # PHC
    "Argon",
    "battcrypt",
    "Catena",
    "Lyra2",
    "Makwa",
    "POMELO",
    "Pufferfish",
    "yescrypt",
    # Misc
    "MD[3-6]",
    "RIPEMD(-?[0-9]{3})?",
    "Streebog",
    "Whirpool",
    # Password hashing (non PHC)
    "bcrypt",
    "scrypt",
    "PBKDF[12]?",
]

rules_crypto_schemes = ["PACE", "MAC", "KEM", "(KEX|Key [eE]xchange)", "PKE", "(TLS|SSL)"]

rules_randomness = ["DUAL_EC_DRBG", "DTRNG", "[PT]RNG", "DRBG", "RN[GD]", "RBG"]

rules_block_cipher_modes = ["ECB", "CBC", "CTR", "CFB", "OFB", "GCM", "SIV", "XTR", "CCM", "LRW", "XEX", "XTS"]

rules_ecc_curves = [
    "(?:Curve |curve |)P-(192|224|256|384|521)",
    "(?:brainpool|BRAINPOOL)P[0-9]{3}[rkt][12]",
    "(?:secp|sect|SECP|SECT)[0-9]+?[rk][12]",
    "(?:ansit|ansip|ANSIP|ANSIT)[0-9]+?[rk][12]",
    "(?:anssi|ANSSI)[ ]*FRP[0-9]+?v1",
    "(NIST)? ?[PBK]-[0-9]{3}",
    "numsp[0-9]{3}[td]1",
    "prime[0-9]{3}v[123]",
    "c2[pto]nb[0-9]{3}[vw][123]",
    "FRP256v1",
    "Curve(25519|1174|4417|22103|67254|383187|41417)",
    "Ed(25519|448)",
    "ssc-(160|192|224|256|288|320|384|512)",
    "Tweedle(dee|dum)",
    "(Pallas|Vesta)",
    "JubJub",
    "BLS(12|24)-[0-9]{3}",
    "bn[0-9]{3}",
]

rules_cplc = [
    "IC[ ]*Fabricator",
    "IC[ ]*Type",
    "IC[ ]*Version",
]

rules_crypto_engines = [
    "TORNADO",
    "SmartMX",
    "SmartMX2",
    "NesCrypt",
]

rules_crypto_libs = [
    "(?:NesLib|NESLIB) [v]*[0-9.]+",
    "AT1 Secure .{1,30}? Library [v]*[0-9.]+",
    "AT1 Secure RSA/ECC/SHA library",
    "Crypto Library [v]*[0-9.]+",
    "ATMEL Toolbox [0-9.]+",
    "v1\\.02\\.013",  # Infineon's ROCA-vulnerable library
    "OpenSSL",
    "LibreSSL",
    "BoringSSL",
    "MatrixSSL",
    "Nettle",
    "GnuTLS",
    "libtomcrypt",
    "BearSSL",
    "Botan",
    "Crypto\\+\\+",
    "wolfSSL",
    "mbedTLS",
    "s2n",
    "NSS",
    "libgcrypt",
    "BouncyCastle",
    "cryptlib",
    "NaCl",
    "libsodium",
    "libsecp256k1",
]

rules_IC_data_groups = [r"EF\.DG[1-9][0-6]?", r"EF\.COM", r"EF\.CardAccess", r"EF\.SOD", r"EF\.ChipSecurity"]

rules_side_channels = [
    "[Mm]alfunction",
    "Leak-Inherent",
    "[Pp]hysical [Pp]robing",
    "[pP]hysical [tT]ampering",
    "[Ss]ide.channels?",
    "SPA",
    "DPA",
    "DFA",
    "SIFA",
    "[Ff]+ault [iI]nduction",
    "[Ff]+ault [iI]njection",
    "ROCA",
    "[tT]iming [aA]ttacks?",
    "[Tt]emplate [aA]ttacks?",
    "[Pp]rofiled [aA]ttacks?",
    "[Cc]lustering [aA]ttacks?",
    "[Dd]eep[ -][lL]earning",
    "[Cc]old [bB]oot",
    "[Rr]owhammer",
    "[Rr]everse [eE]ngineering",
    "[Ll]attice [aA]ttacks?",
    "[Oo]racle [aA]ttacks?",
    "[Bb]leichenbacher [aA]ttacks?",
    "[Bb]ellcore [aA]ttacks?",
    "(t-test|TVLA)",
]

rules_certification_process = [
    "[oO]ut of [sS]cope",
    "[\\.\\(].{0,100}?.[oO]ut of [sS]cope..{0,100}?[\\.\\)]",
    ".{0,100}[oO]ut of [sS]cope.{0,100}",
    ".{0,100}confidential document.{0,100}",
    "[sS]ecurity [fF]unction SF\\.[a-zA-Z0-9_]",
]

rules_vulnerabilities = [
    "CVE-[0-9]+?-[0-9]+?",
    "CWE-[0-9]+?",
]

rules_other = [
    "library",
    # 'http[s]*://.+?/'
]

rules_fips_remove_algorithm_ids = [
    # --- HMAC(-SHA)(-1) - (bits) (method) ((hardware/firmware cert) #id) ---
    # + added (and #id) everywhere
    r"HMAC(?:[- –]*SHA)?(?:[- –]*1)?[– -]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[, ]*?\(?(?: |hardware|firmware)*?[\s(\[]*?(?:#|cert\.?|Cert\.?|Certificate|sample)?[\s#]*?)?[\s#]*?(\d{4})(?:[\s#]*and[\s#]*\d+)?",
    r"HMAC(?:[- –]*SHA)?(?:[- –]*1)?[– -]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[, ]*?\(?(?: |hardware|firmware)*?[\s(\[]*?(?:#|cert\.?|Cert\.?|Certificate|sample)?[\s#]*?)?[\s#]*?(\d{3})(?:[\s#]*and[\s#]*\d+)?",
    r"HMAC(?:[- –]*SHA)?(?:[- –]*1)?[– -]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[, ]*?\(?(?: |hardware|firmware)*?[\s(\[]*?(?:#|cert\.?|Cert\.?|Certificate|sample)?[\s#]*?)?[\s#]*?(\d{2})(?:[\s#]*and[\s#]*\d+)?",
    r"HMAC(?:[- –]*SHA)?(?:[- –]*1)?[– -]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[, ]*?\(?(?: |hardware|firmware)*?[\s(\[]*?(?:#|cert\.?|Cert\.?|Certificate|sample)?[\s#]*?)?[\s#]*?(\d{1})(?:[\s#]*and[\s#]*\d+)?",
    # --- same as above, without hw or fw ---
    r"HMAC(?:-SHA)?(?:-1)?[ -]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[, ]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{4})",
    r"HMAC(?:-SHA)?(?:-1)?[ -]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[, ]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{3})",
    r"HMAC(?:-SHA)?(?:-1)?[ -]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[, ]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{2})",
    r"HMAC(?:-SHA)?(?:-1)?[ -]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[, ]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{1})",
    # --- SHS/A - (bits) (method) ((cert #) numbers) ---
    r"SH[SA][-– 123]*(?:;|\/|160|224|256|384|512)?(?:[\s(\[]*?(?:KAT|[Bb]yte [Oo]riented)*?[\s,]*?[\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{4})(?:\)?\[#?\d+\])?(?:[\s#]*?and[\s#]*?\d+)?",
    r"SH[SA][-– 123]*(?:;|\/|160|224|256|384|512)?(?:[\s(\[]*?(?:KAT|[Bb]yte [Oo]riented)*?[\s,]*?[\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{3})(?:\)?\[#?\d+\])?(?:[\s#]*?and[\s#]*?\d+)?",
    r"SH[SA][-– 123]*(?:;|\/|160|224|256|384|512)?(?:[\s(\[]*?(?:KAT|[Bb]yte [Oo]riented)*?[\s,]*?[\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{2})(?:\)?\[#?\d+\])?(?:[\s#]*?and[\s#]*?\d+)?",
    r"SH[SA][-– 123]*(?:;|\/|160|224|256|384|512)?(?:[\s(\[]*?(?:KAT|[Bb]yte [Oo]riented)*?[\s,]*?[\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{1})(?:\)?\[#?\d+\])?(?:[\s#]*?and[\s#]*?\d+)?",
    # --- RSA (bits) (method) ((cert #)) ---
    r"RSA(?:[-– ]*(?:;|\/|512|768|1024|1280|1536|2048|3072|4096|8192)\s\(\[]*?(?:(?:;|\/|KAT|Verify|PSS|\s)*?)?[\s,]*?[\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{4})",
    r"RSA(?:[-– ]*(?:;|\/|512|768|1024|1280|1536|2048|3072|4096|8192)\s\(\[]*?(?:(?:;|\/|KAT|Verify|PSS|\s)*?)?[\s,]*?[\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{3})",
    r"RSA(?:[-– ]*(?:;|\/|512|768|1024|1280|1536|2048|3072|4096|8192)\s\(\[]*?(?:(?:;|\/|KAT|Verify|PSS|\s)*?)?[\s,]*?[\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{2})",
    r"RSA(?:[-– ]*(?:;|\/|512|768|1024|1280|1536|2048|3072|4096|8192)\s\(\[]*?(?:(?:;|\/|KAT|Verify|PSS|\s)*?)?[\s,]*?[\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{1})",
    # --- RSA (SSA) (PKCS) (version) (#) ---
    r"(?:RSA)?[-– ]?(?:SSA)?[- ]?PKCS\s?#?\d(?:-[Vv]1_5| [Vv]1[-_]5)?[\s#]*?(\d{4})?",
    r"(?:RSA)?[-– ]?(?:SSA)?[- ]?PKCS\s?#?\d(?:-[Vv]1_5| [Vv]1[-_]5)?[\s#]*?(\d{3})?",
    r"(?:RSA)?[-– ]?(?:SSA)?[- ]?PKCS\s?#?\d(?:-[Vv]1_5| [Vv]1[-_]5)?[\s#]*?(\d{2})?",
    r"(?:RSA)?[-– ]?(?:SSA)?[- ]?PKCS\s?#?\d(?:-[Vv]1_5| [Vv]1[-_]5)?[\s#]*?(\d{1})?",
    # --- AES (bits) (method) ((cert #)) ---
    r"AES[-– ]*((?: |;|\/|bit|key|128|192|256|CBC)*(?: |\/|;|[Dd]ecrypt|[Ee]ncrypt|KAT|CMAC|CTR|GCM|IV|CBC)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{4})(?:\)?[\s#]*?\[#?\d+\])?(?:[\s#]*?and[\s#]*?(\d+))?",
    r"AES[-– ]*((?: |;|\/|bit|key|128|192|256|CBC)*(?: |\/|;|[Dd]ecrypt|[Ee]ncrypt|KAT|CMAC|CTR|GCM|IV|CBC)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{3})(?:\)?[\s#]*?\[#?\d+\])?(?:[\s#]*?and[\s#]*?(\d+))?",
    r"AES[-– ]*((?: |;|\/|bit|key|128|192|256|CBC)*(?: |\/|;|[Dd]ecrypt|[Ee]ncrypt|KAT|CMAC|CTR|GCM|IV|CBC)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{2})(?:\)?[\s#]*?\[#?\d+\])?(?:[\s#]*?and[\s#]*?(\d+))?",
    r"AES[-– ]*((?: |;|\/|bit|key|128|192|256|CBC)*(?: |\/|;|[Dd]ecrypt|[Ee]ncrypt|KAT|CMAC|CTR|GCM|IV|CBC)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{1})(?:\)?[\s#]*?\[#?\d+\])?(?:[\s#]*?and[\s#]*?(\d+))?",
    # --- Diffie Helman (CVL) ((cert #)) ---
    r"Diffie[-– ]*Hellman[,\s(\[]*?(?:CVL|\s)*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?[\s#]*?(\d{4})",
    r"Diffie[-– ]*Hellman[,\s(\[]*?(?:CVL|\s)*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?[\s#]*?(\d{3})",
    r"Diffie[-– ]*Hellman[,\s(\[]*?(?:CVL|\s)*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?[\s#]*?(\d{2})",
    r"Diffie[-– ]*Hellman[,\s(\[]*?(?:CVL|\s)*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?[\s#]*?(\d{1})",
    # --- DRBG (bits) (method) (cert #) ---
    r"DRBG[ –-]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{4})",
    r"DRBG[ –-]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{3})",
    r"DRBG[ –-]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{2})",
    r"DRBG[ –-]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{1})",
    # --- DES (bits) (method) (cert #)
    r"DES[ –-]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT|CBC|(?:\d(?: and \d)? keying options?))*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)*?[\s#]*?)?[\s#]*?(\d{4})(?:[\s#]*?and[\s#]*?(\d+))?",
    r"DES[ –-]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT|CBC|(?:\d(?: and \d)? keying options?))*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)*?[\s#]*?)?[\s#]*?(\d{3})(?:[\s#]*?and[\s#]*?(\d+))?",
    r"DES[ –-]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT|CBC|(?:\d(?: and \d)? keying options?))*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)*?[\s#]*?)?[\s#]*?(\d{2})(?:[\s#]*?and[\s#]*?(\d+))?",
    r"DES[ –-]*((?:;|\/|160|224|256|384|512)?(?:;|\/| |[Dd]ecrypt|[Ee]ncrypt|KAT|CBC|(?:\d(?: and \d)? keying options?))*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)*?[\s#]*?)?[\s#]*?(\d{1})(?:[\s#]*?and[\s#]*?(\d+))?",
    # --- DSA (bits) (method) (cert #)
    r"DSA[ –-]*((?:;|\/|160|224|256|384|512)?(?: |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{4})",
    r"DSA[ –-]*((?:;|\/|160|224|256|384|512)?(?: |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{3})",
    r"DSA[ –-]*((?:;|\/|160|224|256|384|512)?(?: |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{2})",
    r"DSA[ –-]*((?:;|\/|160|224|256|384|512)?(?: |[Dd]ecrypt|[Ee]ncrypt|KAT)*?[,\s(\[]*?(?:#|cert\.?|sample|Cert\.?|Certificate)?[\s#]*?)?[\s#]*?(\d{1})",
    # --- platforms (#)+ - this is used in modification history ---
    r"[Pp]latforms? #\d+(?:#\d+|,| |-|and)*[^\n]*",
    # --- CVL (#) ---
    r"CVL[\s#]*?(\d{4})",
    r"CVL[\s#]*?(\d{3})",
    r"CVL[\s#]*?(\d{2})",
    r"CVL[\s#]*?(\d{1})",
    # --- PAA (#) ---
    r"PAA[: #]*?\d{4}",
    r"PAA[: #]*?\d{3}",
    r"PAA[: #]*?\d{2}",
    r"PAA[: #]*?\d{1}",
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
    r"(?:#[^\S\r\n]?|Cert\.?(?!.\s)[^\S\r\n]?|Certificate[^\S\r\n]?)(?P<id>\d{4})(?!\d)",
    r"(?:#[^\S\r\n]?|Cert\.?(?!.\s)[^\S\r\n]?|Certificate[^\S\r\n]?)(?P<id>\d{3})(?!\d)",
    r"(?:#[^\S\r\n]?|Cert\.?(?!.\s)[^\S\r\n]?|Certificate[^\S\r\n]?)(?P<id>\d{2})(?!\d)",
    r"(?:#[^\S\r\n]?|Cert\.?(?!.\s)[^\S\r\n]?|Certificate[^\S\r\n]?)(?P<id>\d{1})(?!\d)",
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


def add_rules(rule_dict, group_name, rules, add_sep=True):
    rule_list = [(rule, re.compile(rule + REGEXEC_SEP if add_sep else rule)) for rule in rules]
    rule_dict[group_name] = rule_list


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                            Common rules
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
common_rules: Dict[str, List[Tuple[str, Pattern]]] = {}
add_rules(common_rules, "rules_os", rules_os)
add_rules(common_rules, "rules_standard_id", rules_standard_id)
add_rules(common_rules, "rules_security_level", rules_security_level)
add_rules(common_rules, "rules_security_assurance_components", rules_security_assurance_components)
add_rules(common_rules, "rules_security_functional_components", rules_security_functional_components)
add_rules(common_rules, "rules_cc_claims", rules_cc_claims)
add_rules(common_rules, "rules_javacard", rules_javacard)
add_rules(common_rules, "rules_javacard_api_consts", rules_javacard_api_consts)
add_rules(common_rules, "rules_javacard_packages", rules_javacard_packages)
add_rules(common_rules, "rules_symmetric_crypto", rules_symmetric_crypto)
add_rules(common_rules, "rules_asymmetric_crypto", rules_asymmetric_crypto)
add_rules(common_rules, "rules_pq_crypto", rules_pq_crypto)
add_rules(common_rules, "rules_hashes", rules_hashes)
add_rules(common_rules, "rules_crypto_schemes", rules_crypto_schemes)
add_rules(common_rules, "rules_randomness", rules_randomness)
add_rules(common_rules, "rules_block_cipher_modes", rules_block_cipher_modes)
add_rules(common_rules, "rules_ecc_curves", rules_ecc_curves)
add_rules(common_rules, "rules_cplc", rules_cplc)
add_rules(common_rules, "rules_tee", rules_tee)
add_rules(common_rules, "rules_crypto_engines", rules_crypto_engines)
add_rules(common_rules, "rules_crypto_libs", rules_crypto_libs)
add_rules(common_rules, "rules_IC_data_groups", rules_IC_data_groups)
add_rules(common_rules, "rules_side_channels", rules_side_channels)
add_rules(common_rules, "rules_certification_process", rules_certification_process)
add_rules(common_rules, "rules_vulnerabilities", rules_vulnerabilities)
add_rules(common_rules, "rules_other", rules_other)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                               For CC
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
cc_rules: Dict[str, List[Tuple[str, Pattern]]] = {}
add_rules(common_rules, "rules_vendor", rules_vendor)
add_rules(common_rules, "rules_cert_id", rules_cert_id)
add_rules(common_rules, "rules_protection_profiles", rules_protection_profiles)
add_rules(common_rules, "rules_technical_reports", rules_technical_reports)
add_rules(common_rules, "rules_device_id", rules_device_id)
cc_rules.update(common_rules)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                            For FIPS
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
fips_rules: Dict[str, List[Tuple[str, Pattern]]] = {}
add_rules(fips_rules, "rules_fips_algorithms", rules_fips_remove_algorithm_ids, add_sep=False)
add_rules(fips_rules, "rules_to_remove", rules_fips_to_remove, add_sep=False)
add_rules(fips_rules, "rules_security_level", rules_fips_security_level, add_sep=False)
add_rules(fips_rules, "rules_cert_id", rules_fips_cert, add_sep=False)
fips_common_rules = copy.deepcopy(common_rules)
