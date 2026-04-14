import pytest

from sec_certs.sample.eucc import EUCCCertificate


@pytest.mark.parametrize(
    "input_text, expected_output",
    [
        (
            "Alice Smith a [dot] smith organization [dot] com ( a[dot]smith[at]organization[dot]com ) tel +123456789",
            "Alice Smith a.smith@organization.com tel +123456789",
        ),
        ("%20support [dot] team generic [dot] org ( support[dot]team[at]generic[dot]org )", "support.team@generic.org"),
        (
            "John Smith Doe j [dot] smith corporate [dot] net ( j[dot]smith[at]corporate[dot]net )",
            "John Smith Doe j.smith@corporate.net",
        ),
        ("Generic contact info 987654", "Generic contact info 987654"),
        ("--- Admin . %20 office [at] domain ( office[at]domain[dot]com )", "Admin office@domain.com"),
    ],
)
def test_deobfuscate_contact(input_text, expected_output):
    result = EUCCCertificate.EnisaMetadata._deobfuscate_contact(input_text)
    assert result == expected_output
