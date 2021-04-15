from pathlib import Path
import json

import sec_certs.analyze_certificates as ac


with open('./fips_dataset/fips_full_dataset.json', 'r') as f:
    fips_items = json.loads(f.read())

ac.do_analysis_fips_certs(fips_items, Path('./fips_result/'))
