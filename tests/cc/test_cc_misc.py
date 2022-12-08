from sec_certs.sample.cc_certificate_id import canonicalize


def test_canonicalize_fr():
    assert canonicalize("Rapport de certification 2001/02v2", "FR") == "ANSSI-CC-2001/02v2"
    assert canonicalize("ANSSI-CC 2001/02-R01", "FR") == "ANSSI-CC-2001/02-R01"


def test_canonicalize_de():
    assert canonicalize("BSI-DSZ-CC-0420-2007", "DE") == "BSI-DSZ-CC-0420-2007"


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
