from sec_certs.sample.cc_certificate_id import canonicalize


def test_canonicalize_fr():
    assert canonicalize("Rapport de certification 2001/02v2", "FR") == "ANSSI-CC-2001/02v2"
    assert canonicalize("ANSSI-CC 2001/02-R01", "FR") == "ANSSI-CC-2001/02-R01"


def test_canonicalize_de():
    assert canonicalize("BSI-DSZ-CC-0420-2007", "DE") == "BSI-DSZ-CC-0420-2007"
    assert canonicalize("BSI-DSZ-CC-1004", "DE") == "BSI-DSZ-CC-1004"
    assert canonicalize("BSI-DSZ-CC-0831-V4-2021", "DE") == "BSI-DSZ-CC-0831-V4-2021"
    assert canonicalize("BSI-DSZ-CC-0837-V2-2014-MA-01", "DE") == "BSI-DSZ-CC-0837-V2-2014-MA-01"


def test_canonicalize_us():
    assert canonicalize("CCEVS-VR-VID10015-2008", "US") == "CCEVS-VR-VID-10015-2008"
    assert canonicalize("CCEVS-VR-10880-2018", "US") == "CCEVS-VR-10880-2018"
    assert canonicalize("CCEVS-VR-04-0082", "US") == "CCEVS-VR-0082-2004"


def test_canonicalize_my():
    assert canonicalize("ISCB-5-RPT-C075-CR-v2", "MY") == "ISCB-5-RPT-C075-CR-v2"
    assert canonicalize("ISCB-5-RPT-C046-CR-V1a", "MY") == "ISCB-5-RPT-C046-CR-v1a"
    assert canonicalize("ISCB-3-RPT-C068-CR-1-v1", "MY") == "ISCB-3-RPT-C068-CR-v1"


def test_canonicalize_es():
    assert canonicalize("2011-14-INF-1095-v1", "ES") == "2011-14-INF-1095"


def test_canonicalize_it():
    assert canonicalize("OCSI/CERT/SYS/10/2016", "IT") == "OCSI/CERT/SYS/10/2016/RC"


def test_canonicalize_in():
    assert canonicalize("IC3S/KOL01/ADVA/EAL2/0520/0021 /CR", "IN") == "IC3S/KOL01/ADVA/EAL2/0520/0021/CR"


def test_canonicalize_se():
    assert canonicalize("CSEC2017020", "SE") == "CSEC2017020"
    assert canonicalize("CSEC 2017020", "SE") == "CSEC2017020"


def test_canonicalize_uk():
    assert canonicalize("CERTIFICATION REPORT No. P123", "UK") == "CRP123"
    assert canonicalize("CRP123A", "UK") == "CRP123A"


def test_canonicalize_ca():
    assert canonicalize("383-4-123-CR", "CA") == "383-4-123"
    assert canonicalize("383-4-123P", "CA") == "383-4-123"


def test_canonicalize_jp():
    assert canonicalize("Certification No. C01234", "JP") == "C01234"
    assert canonicalize("CRP-C01234-01", "JP") == "C01234"
    assert canonicalize("JISEC-CC-CRP-C0689-01-2020", "JP") == "C0689"


def test_canonicalize_no():
    assert canonicalize("SERTIT-12", "NO") == "SERTIT-012"


def test_canonicalize_nl():
    assert canonicalize("NSCIB-CC-22-0428888-CR2", "NL") == "NSCIB-CC-22-0428888-CR2"
    assert canonicalize("NSCIB-CC-22-0428888", "NL") == "NSCIB-CC-22-0428888-CR"
    assert canonicalize("CC-22-0428888", "NL") == "NSCIB-CC-22-0428888-CR"
