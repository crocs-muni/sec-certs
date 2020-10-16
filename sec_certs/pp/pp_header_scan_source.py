from enum import Enum

from pp_tags_constants import *


class HeaderType(Enum):
    BSI = 'BSI'

    DCSSI = 'DCSSI'

    #JAPONSKO
    JBMIA = 'JBMIA'
    JISEC = 'JISEC'
    JICSAP = 'JICSAP'

    #KOREA
    KECS = 'KECS'

    CCEVS = 'CCEVS'

    ANSSI = 'ANSSI'

    ANSSI_BSI_COMMON = 'ANSSI_OR_BSI'

    CCN = 'CCN'

    EADS_CASA = 'EADS_CASA'

    ECF = 'ECF'

    PRA = 'PRA'

    MSB = 'MSB'

    CEN_ISSS = 'CEN_ISSS'

    NL = 'NL'
    SE = 'SE'

    TSE = 'TSE'
    TB = 'TB'
    TCG = 'TCG'

    NSA = 'NSA'
    NIAP = 'NIAP'


regex_rules = [
    (HeaderType.BSI,
    'PP Reference.+?Title (?P<' + TAG_PP_TITLE + '>.+)?CC Version (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Version Number (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration (?P<' + TAG_PP_ID + '>.+)?Keywords (?P<' + TAG_KEYWORDS + '>.+)?TOE Overview'),
    (HeaderType.BSI,
    '(?:PP Reference|Identification).+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Editor/Sponsor: (?P<' + TAG_PP_EDITOR + '>.+)?Supported by: (?P<' + TAG_PP_SPONSOR + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Version Number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+?)?\d\.\d (TOE Overview|Base PPs)'),
    (HeaderType.BSI,
    'PP Reference.+?Title:? (?P<' + TAG_PP_TITLE + '>.+)?Version:? (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Date:? (?P<' + TAG_PP_DATE + '>.+)?Authors:? (?P<' + TAG_PP_AUTHORS + '>.+)?Registration:? (?P<' + TAG_PP_REGISTRATOR + '>.+)Certification-ID:? (?P<' + TAG_PP_ID + '>.+)?Evaluation Assurance Level:? (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?CC[ -]Version:? (?P<' + TAG_CC_VERSION + '>.+)?Keywords:? (?P<' + TAG_KEYWORDS + '>.+?)?(1\.3)? Specific [tT]erms'),
    (HeaderType.BSI,
    '(?:Identification |PP Reference).+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Editors?: (?P<' + TAG_PP_EDITOR + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Version Number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration: (?:.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+?)?(1\.2 PP|1\.2 ТОЕ|Protection Profile Overview|1\.2 TOE Overview|Bundesamt f\u00fcr Sicherheit in der Informationstechnik)'),
    (HeaderType.BSI,
    'Title: (?P<' + TAG_PP_TITLE + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Editor(?:\(s\)|s): (?P<' + TAG_PP_EDITOR + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Version Number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 (ТОЕ|TOE|PP) Overview'),
    (HeaderType.BSI,
    'PP Identification.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration: (?P<' + TAG_PP_REGISTRATOR + '>.+)?Certification ID: (?P<' + TAG_PP_ID + '>.+)?This protection profile is hierarchically'),
    (HeaderType.BSI,
    'PP Reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Date (?P<' + TAG_PP_DATE + '>.+)?Author (?P<' + TAG_PP_AUTHORS + '>.+)?Registration (?P<' + TAG_PP_REGISTRATOR + '>.+)?Certi?fication-ID (?P<' + TAG_PP_ID + '>.+)?CC-Version (?P<' + TAG_CC_VERSION + '>.+)?Keywords (?P<' + TAG_KEYWORDS + '>.+)?1\.2 PP Overview'),
    (HeaderType.BSI,
    'PP reference.+?Title:? (?P<' + TAG_PP_TITLE + '>.+)?Sponsor:? (?P<' + TAG_PP_SPONSOR + '>.+)?CC Version:? (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level:? (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status:? (?P<' + TAG_PP_GENERAL_STATUS + '>.+)Version Number:? (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration:? (?P<' + TAG_PP_ID + '>.+)Keywords:? (?P<' + TAG_KEYWORDS + '>.+?)?(?:page \d of \d\d|1\.2(\.)? TOE [oO]verview|TOE Overview)'),
    (HeaderType.BSI,
    'PP Reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Abbreviation: .+?CC version: (?P<' + TAG_CC_VERSION + '>.+)?PP version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Authors: (?P<' + TAG_PP_AUTHORS + '>.+)?Publication Date: (?P<' + TAG_PP_DATE + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.+)?1\.2 Terminology'),
    (HeaderType.BSI,
    'Protection Profile reference.+?PP Title: (?P<' + TAG_PP_TITLE + '>.+)?PP Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Publication Date: (?P<' + TAG_PP_DATE + '>.+)?Author: (?P<' + TAG_PP_AUTHORS + '>.+)?Certification ID: (?P<' + TAG_PP_ID + '>.+)?CC-Version: (?P<' + TAG_CC_VERSION + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 TOE overview'),
    (HeaderType.BSI,
    '(?:PP Reference|Identification).+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Editor/Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Version Number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+?)?\d\.\d (TOE Overview|Base PPs)'),
    (HeaderType.BSI,
    'PP Reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Editors?: (?P<' + TAG_PP_EDITOR + '>.+)?CC version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Version number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 (ТОЕ|TOE|PP) overview'),
    (HeaderType.BSI,
    'Title: (?P<' + TAG_PP_TITLE + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Author: (?P<' + TAG_PP_AUTHORS + '>.+)?Publication date: (?P<' + TAG_PP_DATE + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.+)?CC version: (?P<' + TAG_CC_VERSION + '>.+)?Editor: (?P<' + TAG_PP_EDITOR + '>.+)?General status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+?)?(prEN|\d\.\d PP overview|\d\.\d Protection Profile Overview)'),
    (HeaderType.BSI,
    'Identification.+?Title: (?P<' + TAG_PP_TITLE + '>.+?)?(?:DBMS PP Extended Package Abbreviation: .+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+?)?[EP]P Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Publication Date: (?P<' + TAG_PP_DATE + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 (?:TOE Overview|DBMS PP Extended)'),
    (HeaderType.BSI,
    'Reference Title: (?P<' + TAG_PP_TITLE + '>.+)?Author: (?P<' + TAG_PP_AUTHORS + '>.+)?Editor: (?P<' + TAG_PP_EDITOR + '>.+)?Reference: .+?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?8\.2 Components statement'),
    (HeaderType.BSI,  # TODO pp0100b tuna mame Base PP a PP-configuration rozpoznane ale nemame PP-module, ten je taky isty ako configuration a oboje je velmi podobne Base PP
    '1\.1 Protection Profile identification Title: (?P<' + TAG_PP_TITLE + '>.+)?Author: (?P<' + TAG_PP_AUTHORS + '>.+)?Editor: (?P<' + TAG_PP_EDITOR + '>.+)?Reference: .+?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 TOE overview'),
    (HeaderType.BSI,
    'PP-Referenz.+?Titel: (?P<' + TAG_PP_TITLE + '>.+)?Version des Dokuments: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Datum des Dokuments: (?P<' + TAG_PP_DATE + '>.+)?Allgemeiner Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Registrierung: (?P<' + TAG_PP_ID + '>.+)?Registrierung bei: (?P<' + TAG_PP_REGISTRATOR + '>.+)?CC[ -]Version:? (?P<' + TAG_CC_VERSION + '>.+)?Vertrauenswürdigkeitsstufe(?: des Produktes:|:) (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Auftraggeber und Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Editor: (?P<' + TAG_PP_EDITOR + '>.+)?Stichwörter: (?P<' + TAG_KEYWORDS + '>.+?)?(?:Dieses Schutzprofil wurde|Common Criteria Schutzprofil)'),
    (HeaderType.BSI,
    'PP Reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Authors: (?P<' + TAG_PP_AUTHORS + '>.+)?Certification-ID: (?P<' + TAG_PP_ID + '>.+)?Evaluation Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?CC-Version: (?P<' + TAG_CC_VERSION + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.3 Specific terms'),
    (HeaderType.BSI,
    'Document information Date of issue (?P<' + TAG_PP_DATE + '>.+)?Author\(s\) (?P<' + TAG_PP_AUTHORS + '>.+)?Version number report (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Certification ID (?P<' + TAG_PP_ID + '>.+)?Scheme.+?Sponsor (?P<' + TAG_PP_SPONSOR + '>.+)?Sponsor address.+?CC-EAL number (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Classification (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Report title (?P<' + TAG_PP_TITLE + '>.+)?Report reference name'),
    (HeaderType.BSI,
    'PP-Identifikation.+?PP-Name: (?P<' + TAG_PP_TITLE + '>.+)?2 Zertifizierungs-ID: (?P<' + TAG_PP_ID + '>.+)3 PP-Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?4 Datum: (?P<' + TAG_PP_DATE + '>.+)?5 Antragsteller: .+?6 Autoren: (?P<' + TAG_PP_AUTHORS + '>.+)?7 EVG-Name: .+?8 CC-Version: (?P<' + TAG_CC_VERSION + '>.+)?1\.2 PP-Übersicht'),
    (HeaderType.BSI,
    'PP Reference Title: (?P<' + TAG_PP_TITLE + '>.+)?Version number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?of (?P<' + TAG_PP_DATE + '>.+)?Provided by: (?P<' + TAG_PP_AUTHORS + '>.+)?Technical editors: (?P<' + TAG_PP_EDITOR + '>.+)?Certified by: (?P<' + TAG_PP_REGISTRATOR + '>.+)?under registration number (?P<' + TAG_PP_ID + '>.+)?1\.2 TOE Overview'),
    (HeaderType.BSI,
    'PP Referenz \d Titel: (?P<' + TAG_PP_TITLE + '>.+)?6 Herausgeber: (?P<' + TAG_PP_REGISTRATOR + '>.+)?7 Editoren: (?P<' + TAG_PP_EDITOR + '>.+)?8 Versionsnummer: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?9 Registrierung: (?P<' + TAG_PP_ID + '>.+)?10 Schlüsselwörter: (?P<' + TAG_KEYWORDS + '>.+?)?\fVersion 1\.0,'),
    (HeaderType.BSI,
    'PP Reference PP Name: (?P<' + TAG_PP_TITLE + '>.+)?Certification ID: (?P<' + TAG_PP_ID + '>.+)?PP Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Date: (?P<' + TAG_PP_DATE + '>.+)?Applicant: (?P<' + TAG_PP_REGISTRATOR + '>.+)?Authors: (?P<' + TAG_PP_AUTHORS + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?1\.2 TOE Overview'),
    (HeaderType.BSI,
    'PP Reference Titel: (?P<' + TAG_PP_TITLE + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Editor\(s\): (?P<' + TAG_PP_EDITOR + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Version number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Date: (?P<' + TAG_PP_DATE + '>.+)?Registration-ID: (?P<' + TAG_PP_ID + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 PP Overview'),
    (HeaderType.BSI,
    'Protection Profile information: PP Identification: (?P<' + TAG_PP_TITLE + '>.+)?PP Registration: (?P<' + TAG_PP_ID + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Date: (?P<' + TAG_PP_DATE + '>.+)?Author: (?P<' + TAG_PP_AUTHORS + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Common Criteria Scheme:.+?Common Criteria Testing Lab: (?P<' + TAG_CERT_LAB + '>.+)?Common Criteria conformance: (?P<' + TAG_CC_VERSION + '>.+)?Assurance level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?To download the'),
    (HeaderType.BSI,
    'PP Reference 115 Title: (?P<' + TAG_PP_TITLE + '>.+)?116 TOE.+?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?119 Document date: (?P<' + TAG_PP_DATE + '>.+)?120 Author: (?P<' + TAG_PP_AUTHORS + '>.+)?121 CC version (?P<' + TAG_CC_VERSION + '>.+)?122 (?P<' + TAG_CC_SECURITY_LEVEL + '>EAL: .+)?123 Certification ID: (?P<' + TAG_PP_ID + '>.+)?124 Evaluation.+?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?127 (.+)?128 Because of'),
    (HeaderType.BSI,
    'Protection Profile Reference \d Title (?P<' + TAG_PP_TITLE + '>.+)?5 PP ID (?P<' + TAG_PP_ID + '>.+)?6 Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?7 Published (?P<' + TAG_PP_DATE + '>.+)?8 Sponsor (?P<' + TAG_PP_SPONSOR + '>.+)?9 Author (?P<' + TAG_PP_AUTHORS + '>.+)?10 TOE.+?11 (?P<' + TAG_CC_SECURITY_LEVEL + '>EAL .+)?12 Keywords (?P<' + TAG_KEYWORDS + '>.+)?13 CC Version (?P<' + TAG_CC_VERSION + '>.+)?1\.2 TOE Overview'),
    (HeaderType.BSI,
    'PP Reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Version number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Provided by: (?P<' + TAG_PP_AUTHORS + '>.+)?Technical editors: (?P<' + TAG_PP_EDITOR + '>.+)?Certified by: (?P<' + TAG_PP_REGISTRATOR + '>.+)?under registration number (?P<' + TAG_PP_ID + '>.+)?1\.2 TOE Overview'),
    (HeaderType.BSI,
    'PP-Identifikation.+?Titel: (?P<' + TAG_PP_TITLE + '>.+)?Version des Dokuments: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Datum des Dokuments: (?P<' + TAG_PP_DATE + '>.+)?Allgemeiner Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Registrierung: (?P<' + TAG_PP_ID + '>.+)?CC Version:? (?P<' + TAG_CC_VERSION + '>.+)?Vertrauenswürdigkeitsstufe: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Auftraggeber und Autor: (?P<' + TAG_PP_AUTHORS + '>.+)?Stichwörter: (?P<' + TAG_KEYWORDS + '>.+?)?Dieses Schutzprofil wurde'),
    (HeaderType.BSI,
    'PP-Identifikation.+?Titel: (?P<' + TAG_PP_TITLE + '>.+)?Version des Dokuments: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Datum des Dokuments: (?P<' + TAG_PP_DATE + '>.+)?Allgemeiner Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Registrierung: (?P<' + TAG_PP_ID + '>.+)?Registrierung bei: (?P<' + TAG_PP_REGISTRATOR + '>.+)?CC-Version:? (?P<' + TAG_CC_VERSION + '>.+)?Vertrauenswürdigkeitsstufe: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Auftraggeber und Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Verfasser: (?P<' + TAG_PP_AUTHORS + '>.+)?Stichwörter: (?P<' + TAG_KEYWORDS + '>.+?)?Dieses Schutzprofil wurde'),
    (HeaderType.BSI,
    'PP-Identifikation.+?PP-Name: (?P<' + TAG_PP_TITLE + '>.+?)?(?P<' + TAG_PP_ID + '>BSI-\w{2}-\d{4}).+?PP-Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?3 Datum: (?P<' + TAG_PP_DATE + '>.+)?4 5 Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Antragsteller: .+?6 Autor: (?P<' + TAG_PP_AUTHORS + '>.+)?7 EVG-Name: .+?8 EAL-Stufe: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?9 Suchbegriffe: (?P<' + TAG_KEYWORDS + '>.+)?10 CC-Version: (?P<' + TAG_CC_VERSION + '>\d\.\d)?1 Berücksichtigt wurden alle'),

    (HeaderType.ANSSI_BSI_COMMON,
    'PROTECTION PROFILE IDENTIFICATION.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Publication date: (?P<' + TAG_PP_DATE + '>.+)?Certified by: (?P<' + TAG_PP_REGISTRATOR + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Editor: (?P<' + TAG_PP_EDITOR + '>.+)?Review Committee: (?P<' + TAG_PP_REVIEWER + '>.+)?This Protection Profile is conformant to the Common Criteria version (?P<' + TAG_CC_VERSION + '>.+)?The minimum assurance level for this Protection Profile is (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?PROTECTION PROFILE PRESENTATION'),
    (HeaderType.ANSSI_BSI_COMMON,
    'IDENTIFICATION.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Publication date: (?P<' + TAG_PP_DATE + '>.+)?Certified by: (?P<' + TAG_PP_REGISTRATOR + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Review Committee: (?P<' + TAG_PP_REVIEWER + '>.+)?This Protection Profile is conformant to the Common Criteria version (?P<' + TAG_CC_VERSION + '>.+)?The minimum assurance level for this Protection Profile is (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?PROTECTION PROFILE PRESENTATION'),
    (HeaderType.ANSSI,
    'PP reference.+?Title : (?P<' + TAG_PP_TITLE + '>.+)?Version : (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Authors : (?P<' + TAG_PP_AUTHORS + '>.+)?Evaluation Assurance Level : (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Registration : (?P<' + TAG_PP_REGISTRATOR + '>.+)?Conformant to Version (?P<' + TAG_CC_VERSION + '>.+)?of Common Criteria.+?Key words : (?P<' + TAG_KEYWORDS + '>.+)?A glossary of terms'),
    (HeaderType.ANSSI,
    'Introduction.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Identifications: (?P<' + TAG_PP_ID + '>\S+).*?Editor: (?P<' + TAG_PP_EDITOR + '>.+)?Date: (?P<' + TAG_PP_DATE + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+?)?This Protection Profile'),
    (HeaderType.ANSSI,
    'PP reference .+?Title (?P<' + TAG_PP_TITLE + '>.+)?Reference (?P<' + TAG_PP_ID + '>.+)?Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Sponsor (?P<' + TAG_PP_SPONSOR + '>.+)?CC version (?P<' + TAG_CC_VERSION + '>.+)?Assurance level (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General status (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Key words (?P<' + TAG_KEYWORDS + '>.+)?1\.2 Protection Profile Overview'),
    (HeaderType.ANSSI,
    'PP Reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Version Number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Keywords: ?(?P<' + TAG_KEYWORDS + '>.+)?1\.2 Protection Profile Overview'),
    (HeaderType.ANSSI,
    'PP reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Editor:? (?P<' + TAG_PP_EDITOR + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Version Number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 TOE Overview'),
    (HeaderType.ANSSI,
    '^(?P<' + TAG_PP_TITLE + '>.+)?Evolutive Certification Scheme for.+?Emission Date : (?P<' + TAG_PP_DATE + '>.+)?Reference : (?P<' + TAG_PP_ID + '>.+)?Version : (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Classification :'),
    (HeaderType.ANSSI,
     'Certification report reference.+?Protection profile name (?P<' + TAG_PP_TITLE + '>.+)?Protection profile reference (?P<' + TAG_PP_ID + '>.+)?version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?, (?P<' + TAG_PP_DATE + '>.+)?Evaluation criteria and version (?P<' + TAG_CC_VERSION + '>.+)?Evaluation level imposed by the PP (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Writer\(s\) (?P<' + TAG_PP_AUTHORS + '>.+)?Sponsor (?P<' + TAG_PP_SPONSOR + '>.+)?Evaluation facility (?P<' + TAG_PP_REGISTRATOR + '>.+)?Recognition arrangements'),
    (HeaderType.ANSSI,
     'Title (?P<' + TAG_PP_TITLE + '>.+)?CC revision (?P<' + TAG_CC_VERSION + '>.+)?PP version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Authors (?P<' + TAG_PP_AUTHORS + '>.+)?Keywords (?P<' + TAG_KEYWORDS + '>.+)?\d\.\d Protection Profile Overview'),

    (HeaderType.JBMIA,
    'Reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Version number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Issue Date: (?P<' + TAG_PP_DATE + '>.+)?Editor: (?P<' + TAG_PP_EDITOR + '>.+)?Issuer: (?P<' + TAG_PP_AUTHORS + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.+)?1\.2 TOE Overview'),
    (HeaderType.JISEC,
    'PP attribute.+?Name (?P<' + TAG_PP_TITLE + '>.+)?Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Issue Date (?P<' + TAG_PP_DATE + '>.+)?Provided by (?P<' + TAG_PP_AUTHORS + '>.+)?Supervised by (?P<' + TAG_PP_EDITOR + '>.+)?Certified by (?P<' + TAG_PP_REGISTRATOR + '>.+)?1\.2 TOE Overview'),
    (HeaderType.JISEC,
    'PP reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Version number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Publication date: (?P<' + TAG_PP_DATE + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Certification ID: (?P<' + TAG_PP_ID + '>.+)?Key words: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 TOE overview'),
    (HeaderType.JICSAP,
    'PP [Ii]dentification.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Date: (?P<' + TAG_PP_DATE + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Issuers: (?P<' + TAG_PP_REGISTRATOR + '>.+)?Authors: (?P<' + TAG_PP_AUTHORS + '>.+)?TOE: .+?Registration: (?P<' + TAG_PP_ID + '>.+)?This PP is English'),

    (HeaderType.KECS,
    'PP reference.+?Title (?P<' + TAG_PP_TITLE + '>.+)?Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Evaluation Assurance Level (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Developer (?P<' + TAG_DEVELOPER + '>.+)?Evaluation Criteria .+?Common Criteria version (?P<' + TAG_CC_VERSION + '>.+)?Certification Number (?P<' + TAG_PP_ID + '>.+)?Keywords (?P<' + TAG_KEYWORDS + '>.+)?1\.2\. TOE overview'),
    (HeaderType.KECS,
    'PP Reference.+?Title : (?P<' + TAG_PP_TITLE + '>.+)?2 Protection Profile Version : (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?3 Evaluation Criteria : .+?4 Common Criteria Version : (?P<' + TAG_CC_VERSION + '>.+)?5 Evaluation Assurance Level : (?P<' + TAG_CC_SECURITY_LEVEL + '>.+?)?, (?P<' + TAG_PP_DATE + '>.+?)?6 Developer ?: (?P<' + TAG_DEVELOPER + '>.+)?7 Certification Body : .+?8 Certification Number : (?P<' + TAG_PP_ID + '>.+)?9 Validation Result : (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?10 Keywords : (?P<' + TAG_KEYWORDS + '>.+)?1\.2 TOE Overview'),

    (HeaderType.CCEVS,
    'Identification.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Author: (?P<' + TAG_PP_AUTHORS + '>.+)?Common Criteria Identification: (?P<' + TAG_CC_VERSION + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?Evaluation Assurance Level \(EAL\): (?P<' + TAG_CC_SECURITY_LEVEL + '>.{5,15}) (?:F\.2 Acknowledgements|)'),

    (HeaderType.DCSSI,
    'Protection profile reference[ ]*Title: (?P<' + TAG_PP_TITLE + '>.+)?Reference: (?P<' + TAG_PP_ID + '>.+)?, Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?, (?P<' + TAG_PP_DATE + '>.+)?Author: (?P<' + TAG_PP_AUTHORS + '>.+)?Context'),
    (HeaderType.DCSSI,
    'Protection profile reference[ ]*Title: (?P<' + TAG_PP_TITLE + '>.+)?Author: (?P<' + TAG_PP_AUTHORS + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Context'),
    (HeaderType.DCSSI,
    'Direction centrale de la sécurité des systèmes d\’information(?P<' + TAG_PP_TITLE + '>.+)?(?:Creation date|Date)[ ]*[:]*(?P<' + TAG_PP_DATE + '>.+)?Reference[ ]*[:]*(?P<' + TAG_PP_ID + '>.+)?Version[ ]*[:]*(?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Courtesy Translation[ ]*Courtesy translation.+?under the reference (?P<' + TAG_PP_ID_REGISTRATOR + '>DCSSI-PP-[0-9/]+)?\.[ ]*Page'),
    (HeaderType.DCSSI,
    'Direction centrale de la sÃ©curitÃ© des systÃ¨mes dâ€™information (?P<' + TAG_PP_TITLE + '>.+)?(?:Creation date|Date)[ ]*:(?P<' + TAG_PP_DATE + '>.+)?Reference[ ]*:(?P<' + TAG_PP_ID + '>.+)?Version[ ]*:(?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Courtesy Translation[ ]*Courtesy translation.+?under the reference (?P<' + TAG_PP_ID_REGISTRATOR + '>DCSSI-PP-[0-9/]+)?\.[ ]*Page'),
    (HeaderType.DCSSI,
    'Protection Profile identification[ ]*Title[ ]*[:]*(?P<' + TAG_PP_TITLE + '>.+)?Author[ ]*[:]*(?P<' + TAG_PP_AUTHORS + '>.+)?Version[ ]*[:]*(?P<' + TAG_PP_VERSION_NUMBER + '>.+)?,(?P<' + TAG_PP_DATE + '>.+)?Sponsor[ ]*[:]*(?P<' + TAG_PP_SPONSOR + '>.+)?CC version[ ]*[:]*(?P<' + TAG_CC_VERSION + '>.+)?(?:Context|Protection Profile introduction)'),
    (HeaderType.DCSSI,
    'PP reference.+?Title[ ]*:(?P<' + TAG_PP_TITLE + '>.+)?Author[ ]*:(?P<' + TAG_PP_AUTHORS + '>.+)?Version[ ]*:(?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Date[ ]*:(?P<' + TAG_PP_DATE + '>.+)?Sponsor[ ]*:(?P<' + TAG_PP_SPONSOR + '>.+)?CC version[ ]*:(?P<' + TAG_CC_VERSION + '>.+)?This protection profile.+?The evaluation assurance level required by this protection profile is (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?specified by the DCSSI qualification process'),
    (HeaderType.DCSSI,
    'Profil de Protection (?P<' + TAG_PP_TITLE + '>.+)?Date de publication : (?P<' + TAG_PP_DATE + '>.+)?Référence : (?P<' + TAG_PP_ID + '>.+)?Version : (?P<' + TAG_PP_VERSION_NUMBER + '>\d\.\d)'),
    (HeaderType.DCSSI,
    'Identification.+?Title (?P<' + TAG_PP_TITLE + '>.+)?Author (?P<' + TAG_PP_AUTHORS + '>.+)?CC Version (?P<' + TAG_CC_VERSION + '>.+)?Reference (?P<' + TAG_PP_ID + '>.+)?Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Key[ ]?words (?P<' + TAG_KEYWORDS + '>.+)?Table[ ]?1 Protection profile identification'),
    (HeaderType.DCSSI,
    'Identification of the Document Author: (?P<' + TAG_PP_AUTHORS + '>.+?)?Title: (?P<' + TAG_PP_TITLE + '>.+?)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+?)?, (?P<' + TAG_PP_DATE + '>.+?)?1\.1\.2 On the Conformance of Security Targets'),  #TODO toto je zle, jcsppc.pdf obsahuje viac PP nielen toto
    (HeaderType.DCSSI,
    'Protection Profile Authors?: (?P<' + TAG_PP_AUTHORS + '>.+?)?Title: (?P<' + TAG_PP_TITLE + '>.+?)?(?:Java CardTM.+?)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+?)?, (?P<' + TAG_PP_DATE + '>.+?)Registration number: (?P<' + TAG_PP_ID + '>.+?)?PP organization:'),
    (HeaderType.DCSSI,
    'Page 1/\d\d (?P<' + TAG_PP_TITLE + '>.+)?Version : (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Date : (?P<' + TAG_PP_DATE + '>.+)?Classification : (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Référence : (?P<' + TAG_PP_ID + '>.+?)?\fProfil de protection'),

    (HeaderType.CCN,
    'PP Identification.+?Title (?P<' + TAG_PP_TITLE + '>.+)?Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Date (?P<' + TAG_PP_DATE + '>.+)?Sponsor (?P<' + TAG_PP_SPONSOR + '>.+)?CC Version (?P<' + TAG_CC_VERSION + '>.+)?CC Evaluation Level (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?1\.2 PP Overview[ ]?of'),
    (HeaderType.CCN,
     'TÍTULO: (?P<' + TAG_PP_TITLE + '>.+)?VERSIÓN (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?FECHA DE EDICIÓN: (?P<' + TAG_PP_DATE + '>.+)?FICHERO.+?AUTORES: (?P<' + TAG_PP_AUTHORS + '>.+)?COMPAÑÍA:'),

    (HeaderType.EADS_CASA,
    'Table 3\. Definitions (?P<' + TAG_PP_ID + '>.+?)?Edic\./Issue B PAG\. \d 1\. PP INTRODUCTION.+?PP Reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Common Criteria Version: (?P<' + TAG_CC_VERSION + '>.+)?Author: (?P<' + TAG_PP_AUTHORS + '>.+)?Publication Date: (?P<' + TAG_PP_DATE + '>.+)?1\.2 TOE Type'),

    (HeaderType.ECF,
    'Title: (?P<' + TAG_PP_TITLE + '>.+?)?Version number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+?)?, issue (?P<' + TAG_PP_DATE + '>.+?)?\. Registration: registered at (?P<' + TAG_PP_REGISTRATOR + '>.+?)?under the number (?P<' + TAG_PP_ID + '>.+?)?\.'),
    (HeaderType.ECF,
    'PP identification Title : (?P<' + TAG_PP_TITLE + '>.+)?Version : (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Author : (?P<' + TAG_PP_AUTHORS + '>.+)?Evaluation Assurance Level : (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Registration : (?P<' + TAG_PP_ID + '>.+)?given by the (?P<' + TAG_PP_REGISTRATOR + '>.+)?at the protection.+?Version (?P<' + TAG_CC_VERSION + '>.+)? of Common Criteria.+?Key words : (?P<' + TAG_KEYWORDS + '>.+)?A glossary of terms'),
    (HeaderType.ECF,
    'PP Identification Title : (?P<' + TAG_PP_TITLE + '>.+)?Version : (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?, issue (?P<' + TAG_PP_DATE + '>.+)?Registration : registered at (?P<' + TAG_PP_REGISTRATOR + '>.+)?under the number (?P<' + TAG_PP_ID + '>.+)?Registration Version.+?version (?P<' + TAG_CC_VERSION + '>.+)?A glossary of terms'),
    (HeaderType.ECF,
    'PP Identification.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?, Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?, (?P<' + TAG_PP_DATE + '>.+)?\. Registration: (?P<' + TAG_PP_ID + '>.+)?1 - PP introduction.+?Assurance level for this PP is (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?\. 8 A product'),
    (HeaderType.ECF,
    'Identification du profil de protection Titre : (?P<' + TAG_PP_TITLE + '>.+)?Enregistrement : (?P<' + TAG_PP_ID + '>.+)?Mots clés : (?P<' + TAG_KEYWORDS + '>.+)?Un glossaire des.+de la version (?P<' + TAG_CC_VERSION + '>.+?)?des Crit\u00e8res Communs'),
    (HeaderType.ECF,
    'Identification du profil de protection Titre : (?P<' + TAG_PP_TITLE + '>.+?)?- V(?P<' + TAG_PP_VERSION_NUMBER + '>.+?)?- (?P<' + TAG_PP_DATE + '>.+?)?Enregistrement : (?P<' + TAG_PP_ID + '>.+)?Mots clés : (?P<' + TAG_KEYWORDS + '>.+)?Référence à d\'autres'),
    (HeaderType.ECF,
    'PP Identification.+?Title: (?P<' + TAG_PP_TITLE + '>.+?)?, Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+?)?, (?P<' + TAG_PP_DATE + '>.+?)?\. Version for.+?Registration: (?P<' + TAG_PP_ID + '>.+?)?1 - PP introduction Intersector'),
    (HeaderType.ECF,
    'PP Identification.+?Title : (?P<' + TAG_PP_TITLE + '>.+)?Version number (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?issued (?P<' + TAG_PP_DATE + '>.+?)?Registration : Origin :(?P<' + TAG_PP_AUTHORS + '>.+)?A glossary of terms.+registered under reference (?P<' + TAG_PP_ID + '>.+?)?,'),
    (HeaderType.ECF,
    'PP IDENTIFICATION.+?TITLE : (?P<' + TAG_PP_TITLE + '>.+)?REGISTRATION : (?P<' + TAG_PP_ID + '>.+)?KEYWORDS : (?P<' + TAG_KEYWORDS + '>.+)?1\.2\. PP OVERVIEW'),
    (HeaderType.ECF,
    'Identification of the Protection Profile \(PP\).+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Reference: (?P<' + TAG_PP_ID + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?I\.2 General outline'),
    (HeaderType.ECF,  # TODO mozeme mergnut s ECF_TYPE1 ??
    'PP Identification.+?Title : (?P<' + TAG_PP_TITLE + '>.+)?Version : (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?, issue (?P<' + TAG_PP_DATE + '>.+)?Registration : Registered at (?P<' + TAG_PP_REGISTRATOR + '>.+)?under the number (?P<' + TAG_PP_ID + '>.+?)?\.'),

    (HeaderType.PRA,
    'PP Reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Editor\(s\): (?P<' + TAG_PP_EDITOR + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Version Number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.+)?Key words: (?P<' + TAG_KEYWORDS + '>.+)?Note:'),

    (HeaderType.MSB,
    'PP reference.+?PP Title (?P<' + TAG_PP_TITLE + '>.+)?PP Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?TOE .+?Evaluation Assurance Level (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?CC Version (?P<' + TAG_CC_VERSION + '>.+)?PP Author (?P<' + TAG_PP_AUTHORS + '>.+?)?\fProtection Profile \d'),
    (HeaderType.MSB,
     'PP reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?TOE Type: .+?Evaluation Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?PP Author: (?P<' + TAG_PP_AUTHORS + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 (?:TOE )?Overview'),
    (HeaderType.MSB,
     'PP Reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Date: (?P<' + TAG_PP_DATE + '>.+)?PP Author: (?P<' + TAG_PP_AUTHORS + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 TOE Type'),

    (HeaderType.CEN_ISSS,
    'Identification.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Authors: (?P<' + TAG_PP_AUTHORS + '>.+)?Vetting Status: .*CC Version: (?P<' + TAG_CC_VERSION + '>.+)?General Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Version Number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.*)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?The following final interpretation'),
    (HeaderType.CEN_ISSS,
    'Identification.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Authors: (?P<' + TAG_PP_AUTHORS + '>.+)?Vetting Status:.+?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?General Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Version Number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration: (?P<' + TAG_PP_ID + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 Protection Profile Overview'),

    (HeaderType.TSE,
    'PP Reference.+?Title : (?P<' + TAG_PP_TITLE + '>.+)?Sponsor : (?P<' + TAG_PP_SPONSOR + '>.+)?Editor\(s\) : Prepared by (?P<' + TAG_PP_AUTHORS + '>.+)?Approved by (?P<' + TAG_PP_EDITOR + '>.+)?CC Version : (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level : (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status : (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Version Number : (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Registration : (?P<' + TAG_PP_ID + '>.+)?Key words : (?P<' + TAG_KEYWORDS + '>.+)?Note :'),
    (HeaderType.TSE,
    'in the table below\..+?Protection Profile[ ]?Name (?P<' + TAG_PP_TITLE + '>.+)?Document Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Publication Date (?P<' + TAG_PP_DATE + '>.+)?Conforming CC Version (?P<' + TAG_CC_VERSION + '>.+)?Conforming EAL (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Keywords (?P<' + TAG_KEYWORDS + '>.+)?1\.2\. DEFINITION OF AIMS'),
    (HeaderType.TSE,
    'PP Reference.+?Title (?P<' + TAG_PP_TITLE + '>.+)?Version (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Publication date (?P<' + TAG_PP_DATE + '>.+)?Authors (?P<' + TAG_PP_AUTHORS + '>.+)? Evaluation Assurance Level \(EAL\) (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?1\.2 Goal and the Scope'),
    (HeaderType.TSE,
     'Title:(?P<' + TAG_PP_TITLE + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?Editor\(s\): (?P<' + TAG_PP_EDITOR + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?General Status: (?P<' + TAG_PP_GENERAL_STATUS + '>.+)?Version Number(?: \/ Revision Date)?: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?(?:as of|\/) (?P<' + TAG_PP_DATE + '>.+)?Registration ?: (?P<' + TAG_PP_ID + '>.+)?Key words ?: (?P<' + TAG_KEYWORDS + '>.+)?Note:'),
    (HeaderType.TB,
    'PP REFERENCE.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance Level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Version Number: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 TOE OVERVIEW'),

    (HeaderType.TCG,
    'PP Reference.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?Sponsor: (?P<' + TAG_PP_SPONSOR + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Assurance level: (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?Document version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?2\.2 TOE Overview'),
    (HeaderType.TCG,
    'PP Reference Title: (?P<' + TAG_PP_TITLE + '>.+)?Version: (?P<' + TAG_CC_VERSION + '>.+)?; (?P<' + TAG_PP_DATE + '>.+)?Author: (?P<' + TAG_PP_AUTHORS + '>.+)?Publication date: (?:.+)?1\.2\. PP organization'),

    (HeaderType.NSA,
    'Identification.+?Title: (?P<' + TAG_PP_TITLE + '>.+)?PP Version: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)?CC:.+?conformant, (?P<' + TAG_CC_SECURITY_LEVEL + '>.+)?CC Version: (?P<' + TAG_CC_VERSION + '>.+)?Keywords: (?P<' + TAG_KEYWORDS + '>.+)?1\.2 Conformance Claims'),

    (HeaderType.NIAP,
    '^\d?(?P<' + TAG_PP_TITLE + '>.+?)Version: (?P<' + TAG_PP_VERSION_NUMBER + '>\d\.\d\.?\d?)? (?P<' + TAG_PP_DATE + '>[12]\d{3}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]))? National Information Assurance Partnership'),

    (HeaderType.CCN,
    'Título: (?P<' + TAG_PP_TITLE + '>.+)?\d\d Título corto: .*, (?P<' + TAG_CC_SECURITY_LEVEL + '>EAL.+)?\d\d Versión: (?P<' + TAG_PP_VERSION_NUMBER + '>.+)\d\d Autor: (?P<' + TAG_PP_AUTHORS + '>.+)?\d\d Fecha de publicación: (?P<' + TAG_PP_DATE + '>.+)?Resumen del TOE'),
]


# These are only special cases of headers; user created database
header_db_source = {
    "pp0013b": [{TAG_PP_TITLE: 'Low Assurance Protection Profile for  VPN gateway', TAG_PP_VERSION_NUMBER: '1.4', TAG_PP_DATE: '29/04/2005', TAG_PP_SPONSOR: 'SRC Security Research & Consulting GmbH, Graurheindorfer Straße 149a, D-53117 Bonn, Germany, Phone: +49 (228) 2806-0, Fax: +49 (228) 2806-199', TAG_PP_ID: 'BSI-PP-0013', TAG_PP_AUTHORS: 'Dirk Feldhusen, Sandro Amendola', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.BSI.value}],
    "Alcohol Interlock Protection Profile v1.00": [{TAG_PP_TITLE: 'Alcohol Interlock Protection Profile', TAG_PP_VERSION_NUMBER: '1.0', TAG_PP_AUTHORS: 'Brightsight BV', TAG_PP_DATE: '31/08/2010', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.NL.value}],
    "ANSSI-CC-PP-2016_05 PP": [{TAG_PP_TITLE: 'Common Criteria Protection Profile - Cryptographic Module for Trust Service Providers', TAG_CC_VERSION: 'v3.1 release 4', TAG_PP_VERSION_NUMBER: '0.15', TAG_PP_AUTHORS: 'WG17', TAG_PP_DATE: '29/11/2016', TAG_KEYWORDS: 'cryptographic module', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.ANSSI.value}],
    "c0553_pp": [{TAG_PP_TITLE: 'Protection Profile for Hardcopy Devices', TAG_PP_VERSION_NUMBER: '1.0', TAG_PP_DATE: '10/09/2015', TAG_PP_SPONSOR: 'IPA JISEC (JAPAN), NIAP CCEVS (US)', TAG_PP_AUTHORS: 'MFP Technical Community', TAG_PP_EDITOR: 'Brian Smithson, Ricoh Americas', TAG_KEYWORDS: 'Multifunction Printer, Multifunction Peripheral, MFP, Multifunction Device, MFD, All-in-one, Hardcopy Device, HCD, Printer, Copier, Photocopier, Scanner, Fax', TAG_CC_VERSION: 'Common Criteria version: Version 3.1, Release 4, Part 2 (CCMB-2012-09-002) Extended, and Part 3 (CCMB-2012-09-003) Conformant', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.JISEC.value}],
    "File Encryption PP v.1.0": [{TAG_PP_TITLE: 'File Encryption Protection Profile', TAG_PP_VERSION_NUMBER: '1.0', TAG_PP_DATE: '2018-07-04', TAG_PP_AUTHORS: 'Yi Cheng, atsec information security AB', TAG_KEYWORDS: 'file encryption/decryption, integrity protection, non-repudiation, certificate, certification authority', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.MSB.value}],
    "pp_voip_v1.3": [{TAG_PP_TITLE: 'Protection Profile for Voice Over IP (VoIP) Applications', TAG_PP_DATE: '3 November 2014', TAG_PP_VERSION_NUMBER: '1.3', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.NIAP.value}],
    "pp_wlan_cli_ep_v1.0": [{TAG_PP_TITLE: 'General Purpose Operating Systems Protection Profile / Mobile Device Fundamentals Protection Profile Extended Package (EP) Wireless Local Area Network (WLAN) Clients', TAG_PP_DATE: '08 February 2016', TAG_PP_VERSION_NUMBER: '1.0', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.NIAP.value}],
    "Protection Profile for Smart Meter Minimum Security requirements_v1-0": [{TAG_PP_TITLE: 'Protection Profile for Smart Meter Minimum Security requirements', TAG_PP_VERSION_NUMBER: '1.1', TAG_PP_DATE: '30. October 2019', TAG_PP_AUTHORS: 'Ad-Hoc Group Privacy & Security of the CEN/CENELEC/ETSI Coordination Group on Smart Meters', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.CEN_ISSS.value}],
    "scsugpp": [{TAG_PP_TITLE: 'Smart Card Security Group Smart Card Protection Profile (SCSUG-SCPP)', TAG_PP_VERSION_NUMBER: '3.0', TAG_PP_DATE: '9 September 2001', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.NIAP.value}],
    "pp0024b": [{TAG_PP_TITLE: 'Identity Managemant Protection Profile', TAG_PP_VERSION_NUMBER: '1.17', TAG_PP_GENERAL_STATUS: 'Final', TAG_KEYWORDS: 'Identity Management, Protection Profile, IMPP', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.BSI.value}],
    "PP Information Gateway 20 (3)": [{TAG_PP_TITLE: 'Protection Profile Information Gateway', TAG_PP_VERSION_NUMBER: '2.0', TAG_PP_DATE: '2011-11-07', TAG_PP_EDITOR: 'Combitech AB, Anders Staaf', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.SE.value}],
    "PP Servicios en Red REALSEC": [{TAG_PP_TITLE: 'Perfil de Protección Servicios en Red Realia Technologies S.L.', TAG_PP_VERSION_NUMBER: '2.0', TAG_PP_AUTHORS: 'Realia Technologies S.L.', TAG_PP_DATE: '24‐12‐2010', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.CCN.value}],
    "UNKT-DO-0002 v1-0": [{TAG_PP_TITLE: 'Protection Profile for UK Dual-Interface Authentication Card', TAG_PP_VERSION_NUMBER: '1.0', TAG_PP_SPONSOR: 'UK Identity and Passport Service', TAG_PP_EDITOR: 'SiVenture', TAG_CC_SECURITY_LEVEL: 'EAL4 augmented with ALC_DVS.2 and AVA_VAN.5', TAG_PP_REGISTRATOR_SIMPLIFIED: 'CESG'}],
    "KECS-PP-0821-2017 Korean National PP for Electronic Document Encryption V1.0(eng)": [{TAG_PP_TITLE: 'Korean National Protection Profile for Electronic Document Encryption', TAG_PP_VERSION_NUMBER: '1.0', TAG_CC_SECURITY_LEVEL: 'EAL1+(ATE_FUN.1)', TAG_DEVELOPER: 'National Security Research Institute, Telecommunications Technology Association', TAG_CC_VERSION: 'CC Version 3.1, Revision 5', TAG_PP_ID: 'KECS-PP-0821-2017', TAG_KEYWORDS: 'Document, Encryption'}],
    "PP HSM CMCSOB 14167-2": [{TAG_PP_TITLE: 'Cryptographic Module for CSP Signing Operations with backup – Protection Profile', TAG_CC_VERSION: '3.1 release 3', TAG_PP_VERSION_NUMBER: '0.35', TAG_PP_AUTHORS: 'Rémy Daudigny', TAG_PP_DATE: '2015', TAG_KEYWORDS: 'cryptographic module, CSP signing device, qualified certificate signing, certificate status information signing', TAG_PP_ID: '419221-2', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.ANSSI.value}],
    "pp0109b_pdf" : [{TAG_PP_TITLE: 'IoT Secure Element Protection Profile (IoT-SE-PP)', TAG_PP_VERSION_NUMBER: '1.0.0', TAG_PP_DATE: '2019-12-19', TAG_CC_VERSION: '3.1 Revision 5', TAG_CC_SECURITY_LEVEL: 'EAL4 augmented with AVA_VAN.4 and optionally ALC_FLR.1', TAG_PP_ID: 'BSI-CC-PP-0109', TAG_PP_AUTHORS: 'Secure Communications Alliance (SCA), IoT PP working group:\nShanghai AOH Smart Technology Co., Ltd.\nChengDu JAVEE Microelectronics Co., Ltd.\nESIM Technology Co., Ltd.\nFEITIAN Technologies Co., Ltd.\nHaier Uplus Intelligent Technology (Beijing) Co., Ltd.\nInfineon Technologies AG Co., Ltd.\nNXP Semiconductors B.V.\nSTMicroelectronics\nTechKnowledge Services Group Inc.\nWuHan TianYu Information Industry Co., Ltd.', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.BSI.value}],
    "pp0107b_pdf" : [{TAG_PP_TITLE: 'Cryptographic Service Provider – Time Stamp Service and Audit (PPC-CSP-TS-Au)', TAG_PP_VERSION_NUMBER: '0.9.5', TAG_PP_DATE: 'April 8th 2019', TAG_PP_ID: 'BSI-CC-PP-0107-2019', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.BSI.value},
                     {TAG_PP_TITLE: 'Cryptographic Service Provider (PP CSP)', TAG_PP_VERSION_NUMBER: '0.9.8', TAG_PP_ID: 'BSI-CC-PP-0104-2019'},
                     {TAG_PP_TITLE: 'Protection Profile-Module CSP Time Stamp Service and Audit', TAG_PP_VERSION_NUMBER : '0.9.5', TAG_CC_VERSION: '3.1 Revision 5', TAG_PP_SPONSOR: 'BSI', TAG_PP_GENERAL_STATUS: 'Final', TAG_KEYWORDS: 'cryptographic service provider, time stamp service'}],
    "pp0108b_pdf" : [{TAG_PP_TITLE: 'Cryptographic Service Provider – Time Stamp Service, Audit and Clustering (PPC-CSP-TS-Au-Cl)', TAG_PP_VERSION_NUMBER: '0.9.4', TAG_PP_DATE: 'April 8th 2019', TAG_PP_ID: 'BSI-CC-PP-0108-2019', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.BSI.value},
                     {TAG_PP_TITLE: 'Cryptographic Service Provider (PP CSP)', TAG_PP_VERSION_NUMBER: '0.9.8', TAG_PP_ID: 'BSI-CC-PP-0104-2019'},
                     {TAG_PP_TITLE: 'Protection Profile-Module CSP Time Stamp Service and Audit (PPM-TS-Au)', TAG_PP_VERSION_NUMBER: '0.9.5', TAG_PP_TITLE: 'Protection Profile-Module CSP Clustering (PPM-Cl)', TAG_PP_VERSION_NUMBER: '0.9.4'},
                     {TAG_PP_TITLE: 'Common Criteria Protection Profile Module Cryptographic Service Provider - Clustering', TAG_PP_SPONSOR: 'BSI', TAG_CC_VERSION: '3.1 Revision 5', TAG_PP_GENERAL_STATUS: 'Final', TAG_PP_VERSION_NUMBER: '0.9.4', TAG_KEYWORDS: 'cryptographic service provider, clustering'}],
    "pp_app_webbrowser_ep_v2.0" : [{TAG_PP_TITLE: 'Application Software Extended Package for Web Browsers', TAG_PP_VERSION_NUMBER: '2.0', TAG_PP_DATE: '2015-16-06', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.NIAP.value}],
    "pp0112b_pdf" : [{TAG_PP_TITLE: 'Cryptographic Service Provider Light – Time Stamp Service and Audit (PPC-CSPLight-TS-Au)', TAG_PP_VERSION_NUMBER: '1.0', TAG_PP_ID: 'BSI-CC-PP-0112-2020', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.BSI.value},
                     {TAG_PP_TITLE: 'Cryptographic Service Provider Light (PP CSPLight)', TAG_PP_VERSION_NUMBER: '1.0', TAG_PP_ID: 'BSI-CC-PP-0111-2019', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.BSI.value},
                     {TAG_PP_TITLE: 'Protection Profile-Module CSPLight Time Stamp Service and Audit', TAG_PP_VERSION_NUMBER: '1.0', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.BSI.value}],
    "pp0113b_pdf" : [{TAG_PP_TITLE: 'Cryptographic Service Provider Light – Time Stamp Service and Audit - Clustering (PPC-CSPLight-TS-Au-Cl)', TAG_PP_VERSION_NUMBER: '1.0', TAG_PP_ID: 'BSI-CC-PP-0113-2020', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.BSI.value},
                     {TAG_PP_TITLE: 'Cryptographic Service Provider Light (PP CSPLight)', TAG_PP_VERSION_NUMBER: '1.0', TAG_PP_ID: 'BSI-CC-PP-0111-2019', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.BSI.value},
                     {TAG_PP_TITLE: 'Common Criteria Protection Profile Module Cryptographic Service Provider Light - Clustering', TAG_CC_VERSION: '3.1 Revision 5', TAG_PP_GENERAL_STATUS: 'Final', TAG_PP_VERSION_NUMBER: '1.0', TAG_KEYWORDS: 'cryptographic service provider light, clustering', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.BSI.value}],
    "anssi-cc-profil-pp-2019_01en" : [{TAG_PP_TITLE: 'Protection profile for trustworthy systems supporting time stamping', TAG_PP_DATE: '2013-12', TAG_PP_REGISTRATOR_SIMPLIFIED: HeaderType.ANSSI.value}]

}