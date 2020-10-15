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
    '[0-9\\.]+?/TSE-CCCS-[0-9]+?', # Turkis CCCS
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
    'WBIS_V[0-9]\\.[0-9]',
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
    'STARCOS(?: [0-9\\.]+?|)',
    'JCOP[ ]*[0-9]'
    ]

rules_standard_id = [
    'FIPS ?(?:PUB )?[0-9]+-[0-9]+?',
    'FIPS ?(?:PUB )?[0-9]+?',
    'NIST SP [0-9]+-[0-9]+?[a-zA-Z]?',
    'PKCS[ #]*[1-9]+',
    'TLS[ ]*v[0-9\\.]+',
    'TLS[ ]*v[0-9\\.]+',
    'BSI-AIS[ ]*[0-9]+?',
    'AIS[ ]*[0-9]+?',
    'RFC[ ]*[0-9]+?',
    'ISO/IEC[ ]*[0-9]+[-]*[0-9]*',
    'ISO/IEC[ ]*[0-9]+:[ 0-9]+',
    'ISO/IEC[ ]*[0-9]+',
    'ICAO(?:-SAC|)',
    '[Xx]\\.509',
    'RFC [0-9]+'
    ]

rules_security_level = [
    'EAL[ ]*[0-9+]+?',
    'EAL[ ]*[0-9] augmented+?',
    'ITSEC[ ]*E[1-9]*.+?',
    ]

rules_security_assurance_components = [
    r'ACE_[A-Z]{3}(?:\.[0-9]|)',
    r'ACM_[A-Z]{3}(?:\.[0-9]|)',
    r'ACO_[A-Z]{3}(?:\.[0-9]|)',
    r'ADO_[A-Z]{3}(?:\.[0-9]|)',
    r'ADV_[A-Z]{3}(?:\.[0-9]|)',
    r'AGD_[A-Z]{3}(?:\.[0-9]|)',
    r'ALC_[A-Z]{3}(?:\.[0-9]|)',
    r'ATE_[A-Z]{3}(?:\.[0-9]|)',
    r'AVA_[A-Z]{3}(?:\.[0-9]|)',
    r'AMA_[A-Z]{3}(?:\.[0-9]|)',
    r'APE_[A-Z]{3}(?:\.[0-9]|)',
    r'ASE_[A-Z]{3}(?:\.[0-9]|)'
]

rules_security_functional_components = [
    r'FAU_[A-Z]{3}(?:\.[0-9]|)',
    r'FCO_[A-Z]{3}(?:\.[0-9]|)',
    r'FCS_[A-Z]{3}(?:\.[0-9]|)',
    r'FDP_[A-Z]{3}(?:\.[0-9]|)',
    r'FIA_[A-Z]{3}(?:\.[0-9]|)',
    r'FMT_[A-Z]{3}(?:\.[0-9]|)',
    r'FPR_[A-Z]{3}(?:\.[0-9]|)',
    r'FPT_[A-Z]{3}(?:\.[0-9]|)',
    r'FRU_[A-Z]{3}(?:\.[0-9]|)',
    r'FTA_[A-Z]{3}(?:\.[0-9]|)',
    r'FTP_[A-Z]{3}(?:\.[0-9]|)'
]

rules_javacard = [
    #'(?:Java Card|JavaCard)',
    #'(?:Global Platform|GlobalPlatform)',
    r'(?:Java Card|JavaCard) [2-3]\.[0-9](?:\.[0-9]|)',
    r'(?:Java Card|JavaCard) \(version [2-3]\.[0-9](?:\.[0-9]|)\)',
    r'(?:Global Platform|GlobalPlatform) [2-3]\.[0-9]\.[0-9]',
    r'(?:Global Platform|GlobalPlatform) \(version [2-3]\.[0-9]\.[0-9]\)',
    ]

rules_crypto_algs = [
    'RSA[- ]*(?:512|768|1024|1280|1536|2048|3072|4096|8192)',
    'RSASSAPKCS1-[Vv]1_5',
    'SHA[-]*(?:160|224|256|384|512)',
    'AES[-]*(?:128|192|256|)',
    'SHA-1',
    'MD5',
    'HMAC',
    'HMAC-SHA-(?:160|224|256|384|512)',
    '(Diffie-Hellman|DH)',
    'ECDH',
    'ECDSA',
    'EdDSA',
    '3?DES',
    'ECC',
    'DTRNG',
    'TRNG',
    'RN[GD]',
    'RBG'
]

rules_block_cipher_modes = [
    'ECB',
    'CBC',
    'CTR',
    'CFB',
    'OFB',
    'GCM'
]

rules_ecc_curves = [
    'P-(192|224|256|384|521)',
    'brainpoolP[0-9]{3}[rkt][12]',
    '(sec|ansi)[pt].+?[rk][12]',
    'prime[0-9]{3}v[123]',
    'c2[pto]nb[0-9]{3}[vw][123]',
    'FRP256v1',
    'Curve(25519|1174|4417|22103|67254|383187|41417)',
    'Ed(25519|448)',
    'ssc-(160|192|224|256|288|320|384|512)',
    'Tweedle(dee|dum)',
    'JubJub',
    'BLS(12|24)-[0-9]{3}'
]

rules_cplc = [
    'IC[ ]*Fabricator',
    'IC[ ]*Type',
    'IC[ ]*Version',
    ]

rules_crypto_engines = [
    'TORNADO',
    'SmartMX',
    'SmartMX2'
    'NesCrypt',
    ]


rules_crypto_libs = [
    '(?:NesLib|NESLIB) [v]*[0-9.]+',
    'AT1 Secure .{1,30}? Library [v]*[0-9.]+',
    'AT1 Secure RSA/ECC/SHA library',
    'Crypto Library [v]*[0-9.]+',
    'ATMEL Toolbox [0-9.]+',
    'v1.02.013' # Infineon's ROCA-vulnerable library
    ]

rules_IC_data_groups = [
    r'EF\.DG[1-9][0-6]?',
    r'EF\.COM',
    r'EF\.CardAccess',
    r'EF\.SOD',
    r'EF\.ChipSecurity'
]

rules_defenses = [
    '[Mm]alfunction',
    'Leak-Inherent',
    '[Pp]hysical [Pp]robing',
    '[pP]hysical [tT]ampering',
    '[Ss]ide.channels?',
    'SPA',
    'DPA',
    'DFA',
    '[Ff]+ault induction',
    'ROCA',
    ]


rules_certification_process = [
    '[oO]ut of [sS]cope',
    '[\\.\\(].{0,100}?.[oO]ut of [sS]cope..{0,100}?[\\.\\)]',
    '.{0,100}[oO]ut of [sS]cope.{0,100}',
    '.{0,100}confidential document.{0,100}',
    '[sS]ecurity [fF]unction SF\\.[a-zA-Z0-9_]',
    ]

rules_vulnerabilities = [
    'CVE-[0-9]+?-[0-9]+?',
    'CWE-[0-9]+?',
    ]

rules_other = [
    'library',
    #'http[s]*://.+?/'
    ]

#rules_security_target_class
rules = {}
rules['rules_vendor'] = rules_vendor
rules['rules_cert_id'] = rules_cert_id
rules['rules_protection_profiles'] = rules_protection_profiles
rules['rules_technical_reports'] = rules_technical_reports
rules['rules_device_id'] = rules_device_id
rules['rules_os'] = rules_os
rules['rules_standard_id'] = rules_standard_id
rules['rules_security_level'] = rules_security_level
rules['rules_security_assurance_components'] = rules_security_assurance_components
rules['rules_security_functional_components'] = rules_security_functional_components
rules['rules_javacard'] = rules_javacard
rules['rules_crypto_algs'] = rules_crypto_algs
rules['block_cipher_modes'] = rules_block_cipher_modes
rules['rules_ecc_curves'] = rules_ecc_curves
rules['rules_cplc'] = rules_cplc
rules['rules_crypto_engines'] = rules_crypto_engines
rules['rules_crypto_libs'] = rules_crypto_libs
rules['rules_IC_data_groups'] = rules_IC_data_groups
rules['rules_defenses'] = rules_defenses
rules['rules_certification_process'] = rules_certification_process
rules['rules_vulnerabilities'] = rules_vulnerabilities
rules['rules_other'] = rules_other
