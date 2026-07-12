import pytest

from sec_certs.sample.cc_certificate_id import CertificateId, canonicalize, canonicalize_eucc
from sec_certs.sample.cc_eucc_common import PdfData


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
def test_canonicalize_fr_eucc(n):
    # year-month-seq
    assert canonicalize_n(n, "EUCC-3090-2025-10-04", "FR") == "EUCC-3090-2025-4"
    # Short form: year-seq
    assert canonicalize_n(n, "EUCC-3090-2026-36", "FR") == "EUCC-3090-2026-36"
    assert canonicalize_n(n, "EUCC-3090-2025-10_03", "FR") == "EUCC-3090-2025-3"
    assert canonicalize_n(n, "EUCC - 3090 - 2025 - 10 - 04", "FR") == "EUCC-3090-2025-4"
    # ENISA long form
    assert canonicalize_n(n, "EUCC-3090-2025-0000000004-00002", "FR") == "EUCC-3090-2025-4"
    # Old ENISA style with month and 4-digit seq
    assert canonicalize_n(n, "EUCC-3090-2025-10-0004", "FR") == "EUCC-3090-2025-4"
    assert canonicalize_n(n, "EUCC-ANSSI-2025-03-02", "FR") == "EUCC-ANSSI-2025-03-02"


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


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_nl_eucc(n):
    # year-month-seq-revision
    assert canonicalize_n(n, "EUCC-3110-2025-08-2500052-01", "NL") == "EUCC-3110-2025-2500052"
    # ENISA long form
    assert canonicalize_n(n, "EUCC-3110-2025-0002500093-00001", "NL") == "EUCC-3110-2025-2500093"
    # Form without month
    assert canonicalize_n(n, "EUCC-3110-2026-2500077-01", "NL") == "EUCC-3110-2026-2500077"


@pytest.mark.parametrize("n", [1, 2])
def test_canonicalize_eucc_generic(n):
    def canon_n(cert_id):
        for _ in range(n):
            new = canonicalize_eucc(cert_id)
            assert new is not None
            cert_id = new
        return cert_id

    # Real ENISA long forms
    assert canon_n("EUCC-3090-2025-0000000001-00002") == "EUCC-3090-2025-1"
    assert canon_n("EUCC-3110-2025-2500051-01-00000") == "EUCC-3110-2025-2500051"
    assert canon_n("EUCC-3087-2026-0000000004-00000") == "EUCC-3087-2026-4"
    assert canon_n("EUCC-3095-2026-0000000005-00000") == "EUCC-3095-2026-5"
    # Bodies with no dedicated scheme rules
    assert canon_n("EUCC-3100-2026-0007001701-00000") == "EUCC-3100-2026-7001701"
    assert canon_n("EUCC-3135-2026-0000000001-00000") == "EUCC-3135-2026-1"


def test_canonicalize_eucc_non_eucc_returns_none():
    # Non-numeric body
    assert canonicalize_eucc("EUCC-ANSSI-2025-03-02") is None
    assert canonicalize_eucc("ANSSI-CC-2014/01") is None
    assert canonicalize_eucc("NSCIB-CC-22-0428888-CR2") is None
    assert canonicalize_eucc("not an id") is None


def test_canonicalize_eucc_matches_scheme_canonicalization():
    # if EUCC section and the CC section produce identical ids
    for cert_id, scheme in [
        ("EUCC-3090-2025-0000000004-00002", "FR"),
        ("EUCC-3090-2025-10-04", "FR"),
        ("EUCC-3090-2026-36", "FR"),
        ("EUCC-3110-2025-08-2500052-01", "NL"),
        ("EUCC-3110-2025-0002500093-00001", "NL"),
        ("EUCC-3110-2026-2500077-01", "NL"),
    ]:
        assert canonicalize_eucc(cert_id) == canonicalize(cert_id, scheme)


def test_certid_compare():
    cid1 = CertificateId("AU", "Certification Report 2007/02")
    cid2 = CertificateId("AU", "Certificate Number: 02/2007")
    cid3 = CertificateId("AU", "Certificate Number: 05/2007")
    assert cid1 == cid2
    assert cid1 != cid3


def test_filename_cert_id_fr():
    def get_id(fname):
        res = PdfData(report_filename=fname).filename_cert_id("FR")
        return list(res.keys())[0] if res else None

    assert get_id("EUCC-3090-2025_10_04_Rapport.pdf") == "EUCC-3090-2025-4"
    assert get_id("EUCC-3090-2026-36-rapport.pdf") == "EUCC-3090-2026-36"
    assert get_id("EUCC-3090-2026_10-rapport.pdf") == "EUCC-3090-2026-10"
    # ANSSI filenames keep working through guarded old rule
    assert get_id("ANSSI-CC-2009_42fr.pdf") == "ANSSI-CC-2009/42"
    assert get_id("2014-01en.pdf") == "ANSSI-CC-2014/01"
    assert get_id("anssi-cc-2021_45v2.pdf") == "ANSSI-CC-2021/45v2"
    # EUCC filename without the CB number cannot be resolved -> none
    assert get_id("EUCC-2025_10_05_Rapport.pdf") is None


def test_filename_cert_id_nl():
    def get_id(fname):
        res = PdfData(report_filename=fname).filename_cert_id("NL")
        return list(res.keys())[0] if res else None

    assert get_id("EUCC-3110-2025-08-2500052-01_CR.pdf") == "EUCC-3110-2025-2500052"
    assert get_id("EUCC-3110-2026-01-2500076-01_CR.pdf") == "EUCC-3110-2026-2500076"
    assert get_id("NSCIB-CC-22-0428888-CR2.pdf") == "NSCIB-CC-22-0428888-CR2"
    assert get_id("CC-16-31801-CR4.pdf") == "NSCIB-CC-16-31801-CR4"
