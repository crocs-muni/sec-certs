import copy
import re
from typing import Dict, List, Pattern

REGEXEC_SEP = r"[ ,;\]”)(]"

rules_cert_id = [
    "BSI-DSZ-CC-[0-9]+?-[0-9]+",  # German BSI
    "BSI-DSZ-CC-[0-9]+?-(?:V|v)[0-9]+-[0-9]+",  # German BSI
    "BSI-DSZ-CC-[0-9]+?-(?:V|v)[0-9]+",  # German BSI
    # 'CC-Zert-.+?',
    "ANSSI(?:-|-CC-)[0-9]+?/[0-9]+",  # French
    # 'ANSSI-CC-CER-F-.+?', # French
    "DCSSI-[0-9]+?/[0-9]+?",  # French
    "Certification Report [0-9]+?/[0-9]+?",  # French
    "Rapport de certification [0-9]+?/[0-9]+?",  # French
    "NSCIB-CC-[0-9][0-9][0-9][0-9].+?",  # Netherlands
    "NSCIB-CC-[0-9][0-9][0-9][0-9][0-9]*-CR",  # Netherlands
    "NSCIB-CC-[0-9][0-9]-[0-9]+?-CR[0-9]+?",  # Netherlands
    "SERTIT-[0-9]+?",  # Norway
    "CCEVS-VR-(?:|VID)[0-9]+?-[0-9]+?",  # US NSA
    # '[0-9][0-9\-]+?-CR', # Canada
    "CRP[0-9][0-9][0-9][0-9]*?",  # UK CESG
    "CERTIFICATION REPORT No. P[0-9]+?",  # UK CESG
    "20[0-9][0-9]-[0-9]+-INF-[0-9]+?",  # Spain
    "KECS-CR-[0-9]+?-[0-9]+?",  # Korea
    "KECS-ISIS-[0-9]+?-[0-9][0-9][0-9][0-9]",  # Korea
    "CRP-C[0-9]+?-[0-9]+?",  # Japan
    "ISCB-[0-9]+?-RPT-[0-9]+?",  # Malaysia
    "OCSI/CERT/.+?",  # Italia
    "[0-9\\.]+?/TSE-CCCS-[0-9]+?",  # Turkis CCCS
    "BTBD-.+?",  # Turkis CCCS
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
]

rules_eval_facilities = ["Serma Technologies", "THALES - CEACI"]

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

rules_crypto_algs = [
    "RSA[- ]*(?:512|768|1024|1280|1536|2048|3072|4096|8192)",
    "RSASSAPKCS1-[Vv]1_5",
    "SHA[-]*(?:160|224|256|384|512)",
    "AES[-]*(?:128|192|256|)",
    "SHA-1",
    "MD5",
    "HMAC",
    "HMAC-SHA-(?:160|224|256|384|512)",
    "(Diffie-Hellman|DH)",
    "ECDH",
    "ECDSA",
    "EdDSA",
    "[3T]?DES",
    "ECC",
    "DTRNG",
    "TRNG",
    "RN[GD]",
    "RBG",
    "PACE",
]

rules_block_cipher_modes = [
    "ECB",
    "CBC",
    "CTR",
    "CFB",
    "OFB",
    "GCM",
]

rules_ecc_curves = [
    "(?:Curve |curve |)P-(192|224|256|384|521)",
    "(?:brainpool|BRAINPOOL)P[0-9]{3}[rkt][12]",
    "(?:secp|sect|SECP|SECT)[0-9]+?[rk][12]",
    "(?:ansit|ansip|ANSIP|ANSIT)[0-9]+?[rk][12]",
    "(?:anssi|ANSSI)[ ]*FRP[0-9]+?v1",
    "prime[0-9]{3}v[123]",
    "c2[pto]nb[0-9]{3}[vw][123]",
    "FRP256v1",
    "Curve(25519|1174|4417|22103|67254|383187|41417)",
    "Ed(25519|448)",
    "ssc-(160|192|224|256|288|320|384|512)",
    "Tweedle(dee|dum)",
    "JubJub",
    "BLS(12|24)-[0-9]{3}",
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

rules_defenses = [
    "[Mm]alfunction",
    "Leak-Inherent",
    "[Pp]hysical [Pp]robing",
    "[pP]hysical [tT]ampering",
    "[Ss]ide.channels?",
    "SPA",
    "DPA",
    "DFA",
    "[Ff]+ault [iI]nduction",
    "[Ff]+ault [iI]njection",
    "ROCA",
    "[tT]iming [aA]ttacks?",
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


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                            Common rules
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
common_rules = {}
common_rules["rules_os"] = rules_os
common_rules["rules_standard_id"] = rules_standard_id
common_rules["rules_security_level"] = rules_security_level
common_rules["rules_security_assurance_components"] = rules_security_assurance_components
common_rules["rules_security_functional_components"] = rules_security_functional_components
common_rules["rules_cc_claims"] = rules_cc_claims
common_rules["rules_javacard"] = rules_javacard
common_rules["rules_javacard_api_consts"] = rules_javacard_api_consts
common_rules["rules_javacard_packages"] = rules_javacard_packages
common_rules["rules_crypto_algs"] = rules_crypto_algs
common_rules["rules_block_cipher_modes"] = rules_block_cipher_modes
common_rules["rules_ecc_curves"] = rules_ecc_curves
common_rules["rules_cplc"] = rules_cplc
common_rules["rules_crypto_engines"] = rules_crypto_engines
common_rules["rules_crypto_libs"] = rules_crypto_libs
common_rules["rules_IC_data_groups"] = rules_IC_data_groups
common_rules["rules_defenses"] = rules_defenses
common_rules["rules_certification_process"] = rules_certification_process
common_rules["rules_vulnerabilities"] = rules_vulnerabilities
common_rules["rules_other"] = rules_other


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                               For CC
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# rules_security_target_class
rules = {}
rules["rules_vendor"] = rules_vendor
rules["rules_cert_id"] = rules_cert_id
rules["rules_protection_profiles"] = rules_protection_profiles
rules["rules_technical_reports"] = rules_technical_reports
rules["rules_device_id"] = rules_device_id
rules.update(common_rules)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#                            For FIPS
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
fips_rules_base: Dict[str, List[str]] = {}
fips_rules_base["rules_fips_algorithms"] = rules_fips_remove_algorithm_ids
fips_rules_base["rules_to_remove"] = rules_fips_to_remove
fips_rules_base["rules_security_level"] = rules_fips_security_level
fips_rules_base["rules_cert_id"] = rules_fips_cert
fips_common_rules = copy.deepcopy(common_rules)  # make separate copy not to process cc rules by fips's re.compile

fips_rules: Dict[str, List[Pattern[str]]] = {}

for rule in fips_rules_base:
    fips_rules[rule] = []
    for current_rule in range(len(fips_rules_base[rule])):
        fips_rules[rule].append(re.compile(fips_rules_base[rule][current_rule]))
