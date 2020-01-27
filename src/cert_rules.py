rules_cert_id = [
    'BSI-DSZ-CC-[0-9]+?-[0-9]+', # German BSI
    'BSI-DSZ-CC-[0-9]+?-(?:V|v)[0-9]+-[0-9]+', # German BSI
    'BSI-DSZ-CC-[0-9]+?-(?:V|v)[0-9]+', # German BSI
    'BSI [0-9]+?', # German BSI
    #'CC-Zert-.+?',
    'ANSSI(?:-|-CC-)[0-9]+?/[0-9]+', # French
    #'ANSSI-CC-CER-F-.+?', # French
    'DCSSI-[0-9]+?/[0-9]+?', # French
    'Certification Report [0-9]+?/[0-9]+?', # French
    'Rapport de certification [0-9]+?/[0-9]+?', # French
    'NSCIB-CC-[0-9][0-9][0-9][0-9].+?', # Netherlands
    'NSCIB-CC-[0-9][0-9][0-9][0-9][0-9]*-CR', # Netherlands
    'NSCIB-CC-[0-9][0-9]-[0-9]+?-CR[0-9]+?',  # Netherlands
    'SERTIT-[0-9]+?', # Norway
    'CCEVS-VR-(?:|VID)[0-9]+?-[0-9]+?', # US NSA
    #'[0-9][0-9\-]+?-CR', # Canada
    'CRP[0-9][0-9][0-9][0-9]*?',    # UK CESG
    'CERTIFICATION REPORT No. P[0-9]+?',  # UK CESG
    '20[0-9][0-9]-[0-9]+-INF-[0-9]+?', # Spain
    'KECS-CR-[0-9]+?-[0-9]+?', # Korea
    'KECS-ISIS-[0-9]+?-[0-9][0-9][0-9][0-9]', # Korea
    'CRP-C[0-9]+?-[0-9]+?', # Japan
    'ISCB-[0-9]+?-RPT-[0-9]+?', # Malaysia
    'OCSI/CERT/.+?', # Italia
    '[0-9\.]+?/TSE-CCCS-[0-9]+?', # Turkis CCCS
    'BTBD-.+?', # Turkis CCCS
    ]

rules_vendor = [
    'NXP',
    'Infineon',
    'Samsung',
    '(?:STMicroelectronics|STM)',
    'Feitian',
    'Gemalto',
    'Gemplus',
    'Axalto',
    '(?:Oberthur|OBERTHUR)',
    '(?:Idemia|IDEMIA)',
    '(?:G\&D|G\+D|Giesecke+Devrient|Giesecke \& Devrient)',
    'Philips',
    'Sagem',
    ]

rules_eval_facilities = [
    'Serma Technologies',
    'THALES - CEACI'
    ]

rules_protection_profiles = [
    'BSI-(?:CC[-_]|)PP[-_]*.+?',
    'PP-SSCD.+?',
    'PP_DBMS_.+?'
    #    'Protection Profile',
    'CCMB-20.+?',
    'CCMB-20[0-9]+?-[0-9]+?-[0-9]+?',
    'BSI-CCPP-.+?',
    'ANSSI-CC-PP.+?',
    'WBIS_V[0-9]\.[0-9]',
    'EHCT_V.+?'
    ]

rules_technical_reports = [
    'BSI[ ]*TR-[0-9]+?(?:-[0-9]+?|)',
    ]


rules_device_id = [
    'G87-.+?',
    'ATMEL AT.+?',
    ]

rules_os = [
    'STARCOS(?: [0-9\.]+?|)',
    'JCOP[ ]*[0-9]'
    ]

rules_standard_id = [
    'FIPS[0-9]+-[0-9]+?',
    'FIPS[0-9]+?',
    'PKCS[ #]*[1-9]+',
    'TLS[ ]*v[0-9\.]+',
    'TLS[ ]*v[0-9\.]+',
    'BSI-AIS[ ]*[0-9]+?',
    'AIS[ ]*[0-9]+?',
    'RFC[ ]*[0-9]+?',
    'ISO/IEC[ ]*[0-9]+[-]*[0-9]*',
    'ISO/IEC[ ]*[0-9]+:[ 0-9]+',
    'ISO/IEC[ ]*[0-9]+',
    'ICAO(?:-SAC|)',
    '[Xx]\.509',
    ]

rules_security_level = [
    'EAL[ ]*[0-9+]+?',
    'EAL[ ]*[0-9] augmented+?',
    'ITSEC[ ]*E[1-9]*.+?',
    ]

rules_security_target_class = [
    # Security assurance requirements
    'ACM_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'ADO_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'ADV_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'AGD_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'ALC_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'ATE_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'AVA_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'AMA_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'APE_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'ASE_[A-Z][A-Z][A-Z](?:\.[0-9]|)',

    # Security functional components
    'FAU_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'FCO_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'FCS_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'FDP_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'FIA_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'FMT_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'FPR_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'FPT_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'FRU_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'FTA_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
    'FTP_[A-Z][A-Z][A-Z](?:\.[0-9]|)',
]



rules_javacard = [
    #'(?:Java Card|JavaCard)',
    #'(?:Global Platform|GlobalPlatform)',
    '(?:Java Card|JavaCard) [2-3]\.[0-9](?:\.[0-9]|)',
    '(?:Java Card|JavaCard) \(version [2-3]\.[0-9](?:\.[0-9]|)\)',
    '(?:Global Platform|GlobalPlatform) [2-3]\.[0-9]\.[0-9]',
    '(?:Global Platform|GlobalPlatform) \(version [2-3]\.[0-9]\.[0-9]\)',
    ]

rules_crypto_algs = [
    'RSA[- ]*(?:512|768|1024|1280|1536|2048|3072|4096|8192)',
    'RSASSAPKCS1-[Vv]1_5',
    'SHA[-]*(?:160|224|256|384|512)',
    'AES[-]*(?:128|192|256|)',
    'SHA-1',
    'MD5',
    'HMAC,'
    'HMAC-SHA-(?:160|224|256|384|512)',
    'Diffie-Hellman',
    'ECDSA',
    'DES',
    'ECC',
    'DTRNG',
    'TRNG',
    'RNG',
    ]

rules_ecc_curves = [
    'P-(?:192|224|256|384|521)',
    'brainpool.+?[rkt]+1',
    'brainpoolP{[0-9, ]+}[rkt]+1',
    'secp.+?1',
]

rules_cplc = [
    'IC[ ]*Fabricator',
    'IC[ ]*Type',
    'IC[ ]*Version',
    ]

rules_crypto_engines = [
    'TORNADO',
    'SmartMX',
    ]


rules_crypto_libs = [
    '(?:NesLib|NESLIB) [v]*[0-9.]+',
    'AT1 Secure .{1,30}? Library [v]*[0-9.]+',
    'AT1 Secure RSA/ECC/SHA library',
    'Crypto Library [v]*[0-9.]+',
    'ATMEL Toolbox [0-9.]+',
    'v1.02.013' # Infineon's ROCA-vulnerable library
    ]



rules_defenses = [
    'SPA',
    'DPA',
    'DFA',
    '[Ff]+ault induction',
    'ROCA',
    ]


rules_certification_process = [
    '[oO]ut of [sS]cope',
    '[\.\(].{0,100}?.[oO]ut of [sS]cope..{0,100}?[\.\)]',
    '.{0,100}[oO]ut of [sS]cope.{0,100}',
    '.{0,100}confidential document{0,100}',
    '[sS]ecurity [fF]unction SF\.[a-zA-Z0-9_]',
    ]

rules_vulnerabilities = [
    'CVE-[0-9]+?-[0-9]+?',
    'CWE-[0-9]+?',
    ]

rules_other = [
    'library',
    #'http[s]*://.+?/'
    ]


rules = {}
rules['rules_vendor'] = rules_vendor
rules['rules_cert_id'] = rules_cert_id
rules['rules_protection_profiles'] = rules_protection_profiles
rules['rules_technical_reports'] = rules_technical_reports
rules['rules_device_id'] = rules_device_id
rules['rules_os'] = rules_os
rules['rules_standard_id'] = rules_standard_id
rules['rules_security_level'] = rules_security_level
rules['rules_security_target_class'] = rules_security_target_class
rules['rules_javacard'] = rules_javacard
rules['rules_crypto_algs'] = rules_crypto_algs
rules['rules_ecc_curves'] = rules_ecc_curves
rules['rules_cplc'] = rules_cplc
rules['rules_crypto_engines'] = rules_crypto_engines
rules['rules_crypto_libs'] = rules_crypto_libs
rules['rules_defenses'] = rules_defenses
rules['rules_certification_process'] = rules_certification_process
rules['rules_vulnerabilities'] = rules_vulnerabilities
rules['rules_other'] = rules_other
