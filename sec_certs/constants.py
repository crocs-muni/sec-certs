from enum import Enum


class CertFramework(Enum):
    CC = 'Common Criteria'
    FIPS = 'FIPS'

cc_active_csv_url = 'https://www.commoncriteriaportal.org/products/certified_products.csv'
cc_active_html_url = 'https://www.commoncriteriaportal.org/products/?expand&names'

cc_archived_csv_url = 'https://www.commoncriteriaportal.org/products/certified_products-archived.csv'
cc_archived_html_url = 'https://www.commoncriteriaportal.org/products/?archived=1&expand&names'

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

cc_features = ['name', 'category', 'vendor', 'vendor_web', 'scheme', 'security_level', 'protection_profiles',
               'not_valid_before', 'not_valid_after', 'cert_link', 'cert_report_link', 'security_target_link',
               'maintenances']

cc_categories = {'AC': 'Access Control Devices and Systems',
                 'BP': 'Boundary Protection Devices and Systems',
                 'DP': 'Data Protection',
                 'DB': 'Databases',
                 'DD': 'Detection Devices and Systems',
                 'IC': 'ICs, Smart Cards and Smart Card-Related Devices and Systems',
                 'KM': 'Key Management Systems',
                 'MD': 'Mobility',
                 'MF': 'Multi-Function Devices',
                 'NS': 'Network and Network-Related Devices and Systems',
                 'OS': 'Operating Systems',
                 'OD': 'Other Devices and Systems',
                 'DG': 'Products for Digital Signatures',
                 'TC': 'Trusted Computing'}
