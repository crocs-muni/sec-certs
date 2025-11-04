from pathlib import Path

from sec_certs.configuration import config
from sec_certs.dataset.cc import CCDataset
from sec_certs.dataset.dataset import Dataset
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.dataset.protection_profile import ProtectionProfileDataset
from sec_certs.utils.pdf import DoclingConverter, PDFConverter, PdftotextConverter


def _verify_cc_convert(dataset: CCDataset, data_dir: Path, converter_name: str, dgst: str, has_json: bool):
    for cert in dataset:
        assert cert.state.st.convert_ok
        assert cert.state.report.convert_ok
        assert cert.state.st.txt_path.exists()
        assert cert.state.report.txt_path.exists()
        if has_json:
            assert cert.state.st.json_path.exists()
            assert cert.state.report.json_path.exists()

        if cert.cert_link:
            assert cert.state.cert.convert_ok
            assert cert.state.cert.txt_path.exists()
            if has_json:
                assert cert.state.cert.json_path.exists()

    template_report_txt_path = data_dir / f"templates/{converter_name}/reports/{dgst}.txt"
    template_st_txt_path = data_dir / f"templates/{converter_name}/targets/{dgst}.txt"
    assert abs(dataset[dgst].state.st.txt_path.stat().st_size - template_st_txt_path.stat().st_size) < 1000
    assert abs(dataset[dgst].state.report.txt_path.stat().st_size - template_report_txt_path.stat().st_size) < 1000


def _verify_pp_convert(
    dataset: ProtectionProfileDataset, data_dir: Path, converter_name: str, dgst: str, has_json: bool
):
    for cert in dataset:
        assert cert.state.report.convert_ok
        assert cert.state.pp.convert_ok
        assert cert.state.report.txt_path.exists()
        assert cert.state.pp.txt_path.exists()
        if has_json:
            assert cert.state.report.json_path.exists()
            assert cert.state.pp.json_path.exists()

    template_report_txt_path = data_dir / f"templates/{converter_name}/reports/{dgst}.txt"
    template_pp_txt_path = data_dir / f"templates/{converter_name}/pps/{dgst}.txt"
    assert abs(dataset[dgst].state.report.txt_path.stat().st_size - template_report_txt_path.stat().st_size) < 1000
    assert abs(dataset[dgst].state.pp.txt_path.stat().st_size - template_pp_txt_path.stat().st_size) < 1000


def _verify_fips_convert(dataset: FIPSDataset, data_dir: Path, converter_name: str, dgst: str, has_json: bool):
    for cert in dataset:
        assert cert.state.policy_convert_ok
        assert cert.state.policy_txt_path.exists()
        if has_json:
            assert cert.state.policy_json_path.exists()

    template_policy_txt_path = data_dir / f"templates/{converter_name}/policies/{dgst}.txt"
    assert abs(dataset[dgst].state.policy_txt_path.stat().st_size - template_policy_txt_path.stat().st_size) < 1000


def _verify_converter(
    dataset: Dataset, data_dir: Path, dgst: str, converter: PDFConverter, converter_name: str, has_json: bool
):
    orig_converter = config.pdf_converter
    config.pdf_converter = converter
    dataset.convert_all_pdfs()
    config.pdf_converter = orig_converter

    if isinstance(dataset, CCDataset):
        _verify_cc_convert(dataset, data_dir, converter_name, dgst, has_json)
    if isinstance(dataset, ProtectionProfileDataset):
        _verify_pp_convert(dataset, data_dir, converter_name, dgst, has_json)
    if isinstance(dataset, FIPSDataset):
        _verify_fips_convert(dataset, data_dir, converter_name, dgst, has_json)


def verify_convert_pdfs(dataset: Dataset, data_dir: Path, dgst: str):
    _verify_converter(dataset, data_dir, dgst, PdftotextConverter, "pdftotext", False)
    _verify_converter(dataset, data_dir, dgst, DoclingConverter, "docling", True)
