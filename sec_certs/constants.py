import json
from enum import Enum

N_THREADS = 8
RESPONSE_OK = 200
RETURNCODE_OK = 'ok'
RETURNCODE_NOK = 'nok'
REQUEST_TIMEOUT = 10

MIN_CORRECT_CERT_SIZE = 5000

LOGS_FILENAME = './cert_processing_log.txt'

class CertFramework(Enum):
    CC = 'Common Criteria'
    FIPS = 'FIPS'


TAG_MATCH_COUNTER = 'count'
TAG_MATCH_MATCHES = 'matches'

TAG_CERT_HEADER_PROCESSED = 'cert_header_processed'

TAG_CERT_ID = 'cert_id'
TAG_CC_SECURITY_LEVEL = 'cc_security_level'
TAG_CC_VERSION = 'cc_version'
TAG_CERT_LAB = 'cert_lab'
TAG_CERT_ITEM = 'cert_item'
TAG_CERT_ITEM_VERSION = 'cert_item_version'
TAG_DEVELOPER = 'developer'
TAG_REFERENCED_PROTECTION_PROFILES = 'ref_protection_profiles'
TAG_HEADER_MATCH_RULES = 'match_rules'
TAG_PP_TITLE = 'pp_title'
TAG_PP_GENERAL_STATUS = 'pp_general_status'
TAG_PP_VERSION_NUMBER = 'pp_version_number'
TAG_PP_ID = 'pp_id'
TAG_PP_ID_REGISTRATOR = 'pp_id_registrator'
TAG_PP_DATE = 'pp_date'
TAG_PP_AUTHORS = 'pp_authors'
TAG_PP_REGISTRATOR = 'pp_registrator'
TAG_PP_REGISTRATOR_SIMPLIFIED = 'pp_registrator_simplified'
TAG_PP_SPONSOR = 'pp_sponsor'
TAG_PP_EDITOR = 'pp_editor'
TAG_PP_REVIEWER = 'pp_reviewer'
TAG_KEYWORDS = 'keywords'
FIPS_NOT_AVAILABLE_CERT_SIZE = 10000
FIPS_ALG_URL = 'https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/validation-search?searchMode=validation&page='


SAR_string_mapping = {}
SAR_string_mapping['ACM_AUT'] = 'Configuration management: Automation'
SAR_string_mapping['ACM_CAP'] = 'Configuration management: Capabilities'
SAR_string_mapping['ACM_SCP'] = 'Configuration management: Scope'

SAR_string_mapping['ADO_DEL'] = 'Delivery and operation: Delivery'
SAR_string_mapping['ADO_IGS'] = 'Delivery and operation: Installation, generation and start-up'

SAR_string_mapping['ADV_FSP'] = 'Development: Functional specification'
SAR_string_mapping['ADV_HLD'] = 'Development: High-level design'
SAR_string_mapping['ADV_IMP'] = 'Development: Implementation representation'
SAR_string_mapping['ADV_INT'] = 'Development: TSF internals'
SAR_string_mapping['ADV_LLD'] = 'Development: Low-level design'
SAR_string_mapping['ADV_RCR'] = 'Development: Representation correspondence'
SAR_string_mapping['ADV_SPM'] = 'Development: Security policy modeling'

SAR_string_mapping['AGD_ADM'] = 'Guidance documents: Administrator guidance'
SAR_string_mapping['AGD_USR'] = 'Guidance documents: User guidance'

SAR_string_mapping['ALC_DVS'] = 'Life cycle support: Development security'
SAR_string_mapping['ALC_FLR'] = 'Life cycle support: Flaw remediation'
SAR_string_mapping['ALC_LCD'] = 'Life cycle support: Life cycle definition'
SAR_string_mapping['ALC_TAT'] = 'Life cycle support: Tools and techniques'
SAR_string_mapping['ALC_CMC'] = 'Life cycle support: Capabilities'
SAR_string_mapping['ALC_CMS'] = 'Life cycle support: scope'


SAR_string_mapping['ATE_COV'] = 'Tests: Coverage'
SAR_string_mapping['ATE_DPT'] = 'Tests: Depth'
SAR_string_mapping['ATE_FUN'] = 'Tests: Functional tests'
SAR_string_mapping['ATE_IND'] = 'Tests: Independent testing'

SAR_string_mapping['AVA_CCA'] = 'Vulnerability assessment: Covert channel analysis'
SAR_string_mapping['AVA_MSU'] = 'Vulnerability assessment: Misuse'
SAR_string_mapping['AVA_SOF'] = 'Strength of TOE security functions'
SAR_string_mapping['AVA_VLA'] = 'Vulnerability assessment: Vulnerability analysis'

SAR_string_mapping['ASE_INT'] = 'ST evaluation: ST introduction'
SAR_string_mapping['ASE_CCL'] = 'ST evaluation: Conformance claims'
SAR_string_mapping['ASE_SPD'] = 'ST evaluation: Security problem definition'
SAR_string_mapping['ASE_OBJ'] = 'ST evaluation: Security objectives'
SAR_string_mapping['ASE_ECD'] = 'ST evaluation: Extended components definition'
SAR_string_mapping['ASE_REQ'] = 'ST evaluation: Security requirements'
SAR_string_mapping['ASE_TSS'] = 'ST evaluation: TOE summary specification'

# SAR_string_mapping['D'] = 'user Data'
# SAR_string_mapping['O'] = 'Objectives'
# SAR_string_mapping['T'] = 'Threats'
# SAR_string_mapping['A'] = 'Assumptions'
# SAR_string_mapping['R'] = 'Requirements'
# SAR_string_mapping['P'] = 'Policy (organisational security)'
# SAR_string_mapping['OT'] = 'security objectives'
# SAR_string_mapping['OP'] = 'OPerations'
# SAR_string_mapping['OE'] = 'Objectives for the Environment'
# SAR_string_mapping['SA'] = 'Security Aspects'
# SAR_string_mapping['OSP'] = 'Organisational Security Policy'



