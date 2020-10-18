import extract_certificates

import os

FILE_ERRORS_STRATEGY = extract_certificates.FILE_ERRORS_STRATEGY


def generate_fips_basic_download_script():
    with open('download_fips_web.bat', 'w', errors=FILE_ERRORS_STRATEGY) as file:
        file.write(
            'curl "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search'
            '/all" -o fips_modules_validated.html\n')


def generate_fips_download_script(file_name, fips_dir):
    """generate_fips_download_script.

    :param file_name: name of the download file
    :param fips_dir: directory for saved files
    """
    html_dir = os.path.join(fips_dir, 'html')
    sp_dir = os.path.join(fips_dir, 'security_policies')

    with open(file_name, 'w', errors=FILE_ERRORS_STRATEGY) as write_file:
        # make directories for both html and security policies, scraping in one go
        write_file.write('mkdir {}\n'.format(html_dir))
        write_file.write('mkdir {}\n\n'.format(sp_dir))

        for cert_id in range(1, 4001):
            write_file.write(
                'curl "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{}" -o {}{}.html\n'.format(
                    cert_id, html_dir, cert_id))
            write_file.write(
                'curl "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents'
                '/security-policies/140sp{}.pdf" -o {}{}.pdf\n'.format(
                    cert_id, sp_dir, cert_id))
            write_file.write("{} {}{}.pdf\n".format(
                extract_certificates.PDF2TEXT_CONVERT, sp_dir, cert_id))
