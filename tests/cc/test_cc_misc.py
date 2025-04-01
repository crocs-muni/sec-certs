import pytest

from sec_certs.sample.cc_certificate_id import CertificateId, canonicalize


def canonicalize_n(n, cert_id_str, scheme):
    cert_id = cert_id_str
    for _ in range(n):
        cert_id = canonicalize(cert_id, scheme)
    return cert_id


def test_meta_parse():
    i = CertificateId("FR", "Rapport de certification 2001/02v2")
    assert "year" in i.meta
    assert i.meta["year"] == "2001"
    assert i.meta["counter"] == "02"
    assert i.meta["version"] == "2"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_fr(n):
    assert canonicalize_n(n, "Rapport de certification 2001/02v2", "FR") == "ANSSI-CC-2001/02v2"
    assert canonicalize_n(n, "ANSSI-CC 2001/02-R01", "FR") == "ANSSI-CC-2001/02-R01"
    assert canonicalize_n(n, "ANSSI-CC 2001_02-M01", "FR") == "ANSSI-CC-2001/02-M01"
    assert canonicalize_n(n, "ANSSI-CC-PP-2013/58", "FR") == "ANSSI-CC-PP-2013/58"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_de(n):
    assert canonicalize_n(n, "BSI-DSZ-CC-0420-2007", "DE") == "BSI-DSZ-CC-0420-2007"
    assert canonicalize_n(n, "BSI-DSZ-CC-1004", "DE") == "BSI-DSZ-CC-1004"
    assert canonicalize_n(n, "BSI_DSZ_CC_0348_2006", "DE") == "BSI-DSZ-CC-0348-2006"
    assert canonicalize_n(n, "BSI-DSZ-CC-0831-V4-2021", "DE") == "BSI-DSZ-CC-0831-V4-2021"
    assert canonicalize_n(n, "BSI-DSZ-CC-0837-V2-2014-MA-01", "DE") == "BSI-DSZ-CC-0837-V2-2014-MA-01"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_us(n):
    assert canonicalize_n(n, "CCEVS-VR-VID10015", "US") == "CCEVS-VR-VID-10015"
    assert canonicalize_n(n, "CCEVS-VR-VID10015-2008", "US") == "CCEVS-VR-VID-10015-2008"
    assert canonicalize_n(n, "CCEVS-VR-10880-2018", "US") == "CCEVS-VR-10880-2018"
    assert canonicalize_n(n, "CCEVS-VR-04-0082", "US") == "CCEVS-VR-0082-2004"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_my(n):
    assert canonicalize_n(n, "ISCB-5-RPT-C075-CR-v2", "MY") == "ISCB-5-RPT-C075-CR-v2"
    assert canonicalize_n(n, "ISCB-5-RPT-C046-CR-V1a", "MY") == "ISCB-5-RPT-C046-CR-v1a"
    assert canonicalize_n(n, "ISCB-3-RPT-C068-CR-1-v1", "MY") == "ISCB-3-RPT-C068-CR-v1"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_es(n):
    assert canonicalize_n(n, "2011-14-INF-1095-v1", "ES") == "2011-14-INF-1095"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_sg(n):
    assert canonicalize_n(n, "CSA_CC_21005", "SG") == "CSA_CC_21005"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_in(n):
    assert canonicalize_n(n, "IC3S/KOL01/ADVA/EAL2/0520/0021 /CR", "IN") == "IC3S/KOL01/ADVA/EAL2/0520/0021"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_it(n):
    assert canonicalize_n(n, "OCSI/CERT/TEC/02/2009/RC", "IT") == "OCSI/CERT/TEC/02/2009/RC"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_se(n):
    assert canonicalize_n(n, "CSEC2017020", "SE") == "CSEC2017020"
    assert canonicalize_n(n, "CSEC 2017020", "SE") == "CSEC2017020"
    assert canonicalize_n(n, "CSEC201003", "SE") == "CSEC2010003"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_uk(n):
    assert canonicalize_n(n, "CERTIFICATION REPORT No. P123", "UK") == "CRP123"
    assert canonicalize_n(n, "CRP123A", "UK") == "CRP123A"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_au(n):
    assert canonicalize_n(n, "Certification Report 2007/02", "AU") == "Certificate Number: 2007/02"
    assert canonicalize_n(n, "Certificate Number: 37/2006", "AU") == "Certificate Number: 2006/37"
    assert canonicalize_n(n, "Certificate Number: 2011/73", "AU") == "Certificate Number: 2011/73"
    assert canonicalize_n(n, "Certification Report 97/76", "AU") == "Certificate Number: 1997/76"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_ca(n):
    assert canonicalize_n(n, "383-4-123-CR", "CA") == "383-4-123"
    assert canonicalize_n(n, "383-4-123P", "CA") == "383-4-123"
    assert canonicalize_n(n, "522 EWA 2020", "CA") == "522-EWA-2020"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_jp(n):
    assert canonicalize_n(n, "Certification No. C01234", "JP") == "JISEC-CC-CRP-C01234"
    assert canonicalize_n(n, "CRP-C01234-01", "JP") == "JISEC-CC-CRP-C01234-01"
    assert canonicalize_n(n, "JISEC-CC-CRP-C0689-01-2020", "JP") == "JISEC-CC-CRP-C0689-01-2020"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_kr(n):
    assert canonicalize_n(n, "KECS-ISIS-0579-2015", "KR") == "KECS-ISIS-0579-2015"
    assert canonicalize_n(n, "KECS-CISS-10-2023", "KR") == "KECS-CISS-0010-2023"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_no(n):
    assert canonicalize_n(n, "SERTIT-12", "NO") == "SERTIT-012"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_tr(n):
    assert canonicalize_n(n, "21.0.03.0.00.00/TSE-CCCS-85", "TR") == "21.0.03.0.00.00/TSE-CCCS-85"
    assert canonicalize_n(n, "21.0.03/TSE-CCCS-33", "TR") == "21.0.03/TSE-CCCS-33"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_nl(n):
    assert canonicalize_n(n, "NSCIB-CC-22-0428888-CR2", "NL") == "NSCIB-CC-22-0428888-CR2"
    assert canonicalize_n(n, "NSCIB-CC-22-0428888", "NL") == "NSCIB-CC-22-0428888-CR"
    assert canonicalize_n(n, "CC-22-0428888", "NL") == "NSCIB-CC-22-0428888-CR"


def test_certid_compare():
    cid1 = CertificateId("AU", "Certification Report 2007/02")
    cid2 = CertificateId("AU", "Certificate Number: 02/2007")
    cid3 = CertificateId("AU", "Certificate Number: 05/2007")
    assert cid1 == cid2
    assert cid1 != cid3
