from pathlib import Path
from typing import List


def generate_html(ids: List[str], path: Path):
    def generate_entry(certificate_id: str) -> str:
        return f"""
            <tr id="cert-row-0">
                <td class="text-center">
                    <a href="/projects/cryptographic-module-validation-program/certificate/3898" id="cert-number-link-0">{certificate_id}</a>
                </td>
            </tr>
        """

    html_head = """
    <!DOCTYPE html>
    <html lang="en-us" xml:lang="en-us">
    <head>
        <meta charset="utf-8" />
        <title>Cryptographic Module Validation Program | CSRC</title>
        <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
        <meta http-equiv="content-style-type" content="text/css" />
        <meta http-equiv="content-script-type" content="text/javascript" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta name="msapplication-config" content="/CSRC/Media/images/favicons/browserconfig.xml" />
        <meta name="theme-color" content="#000000" />
        <meta name="google-site-verification" content="xbrnrVYDgLD-Bd64xHLCt4XsPXzUhQ-4lGMj4TdUUTA" />
    </head>
    """
    rows = ""
    for cert_id in ids:
        rows += f"\n{generate_entry(cert_id)}\n"
    html_body = f"""
    <body>
        <table class="table table-striped table-condensed publications-table table-bordered" id="searchResultsTable">
            <thead>
                <tr>
                    <th class="text-center">Certificate Number</th>
                    <th class="text-center">Vendor Name</th>
                    <th class="text-center">Module Name</th>
                    <th class="text-center">Module Type</th>
                    <th class="text-center">Validation Date</th>
                </tr>
            </thead>
            <tbody>
            {rows}
            </tbody>
        </table>
    </body>
    """
    with open(path, "w") as f:
        f.write(f"{html_head}\n{html_body}\n")
