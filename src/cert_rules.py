rules_cert_id = [
    'BSI-DSZ-CC-[0-9]+?-[0-9]+', # German BSI
    'BSI-DSZ-CC-[0-9]+?-(?:V|v)[0-9]+-[0-9]+', # German BSI
    'BSI-DSZ-CC-[0-9]+?-(?:V|v)[0-9]+', # German BSI
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
    'BSI-(?:CC-|)PP[-]*.+?',
    'PP-SSCD.+?',
    'Protection Profile',
    'CCMB-20.+?',
    'BSI-CCPP-.+?',
    'ANSSI-CC-PP.+?',
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
    'FIPS180-4',
    'FIPS197',
    'PKCS#[1-9]+',
    'TLSv1.1',
    'TLSv1.2',
    'BSI-AIS[ ]*[0-9]+?',
    'AIS[ ]*[0-9]+?',
    'RFC[ ]*[0-9]+?',
    'ISO/IEC 14443',
    'ISO/IEC [0-9]+:[0-9]+',
    ]

rules_security_level = [
    'EAL[ ]*[0-9+]+?',
    'EAL[ ]*[0-9] augmented+?',
    'ITSEC[ ]*E[1-9]*.+?',
    ]

rules_javacard = [
    #'(?:Java Card|JavaCard)',
    #'(?:Global Platform|GlobalPlatform)',
    '(?:Java Card|JavaCard) [2-3]\.[0-9](?:\.[0-9]|)',
    '(?:Global Platform|GlobalPlatform) [2-3]\.[0-9]\.[0-9]',
    ]

rules_crypto_algs = [
    'RSA[- ]*(?:512|768|1024|1280|1536|2048|3072|4096|8192)',
    'RSASSAPKCS1-V1_5',
    'SHA[-]*(?:160|224|256|384|512)',
    'AES[-]*(?:128|192|256|)',
    'SHA-1',
    'MD5',
    'HMAC',
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
    'brainpool.+?',
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
    ]



rules_defenses = [
    'SPA',
    'DPA',
    'DFA',
    '[Ff]+ault induction',
    'ROCA',
    ]


rules_other = [
    'library',
    ]

rules = {}
rules['rules_vendor'] = rules_vendor
rules['rules_cert_id'] = rules_cert_id
rules['rules_protection_profiles'] = rules_protection_profiles
rules['rules_device_id'] = rules_device_id
rules['rules_os'] = rules_os
rules['rules_standard_id'] = rules_standard_id
rules['rules_security_level'] = rules_security_level
rules['rules_javacard'] = rules_javacard
rules['rules_crypto_algs'] = rules_crypto_algs
rules['rules_ecc_curves'] = rules_ecc_curves
rules['rules_cplc'] = rules_cplc
rules['rules_crypto_engines'] = rules_crypto_engines
rules['rules_crypto_libs'] = rules_crypto_libs
rules['rules_defenses'] = rules_defenses
rules['rules_other'] = rules_other
