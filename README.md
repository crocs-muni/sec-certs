# sec-certs

Analyzer of security certificates (Common Criteria, NIST FIPS140-2...) 

## Usage

Steps:
 1. Run `process_certificates.py` to generate download scripts (download_cc_web.bat)
 2. Run `download_cc_web.bat` to download important files from Common Criteria website (requires `curl` installed)
 3. Run `process_certificates.py` to generate download scripts for separate pdf files with certificates (`download_active_certs.bat`, `download_active_updates.bat`...)
 4. Place all download scripts into folder on disk with at least 5GB free space (yes, there are A LOT of certificates) and run them, wait until download and text extraction is completed 
 5. Edit process_certificates.py, create new profile (paths_xxx) with correct paths pointing to the place where you dowloaded certificates, set paths_used = paths_xxx variable to your (see paths_20200904 dict for example). Intermediate files generated during the processing will be created inside `current_path/results_yyy` folder where yyy is value set by you at `paths_xxx['id']`. (DEBUG, remove later)
 6. Run `process_certificates.py` to process CSV, HTML and PDF files. Extracted information is stored in *.json files. `do_extraction` and `do_pairing` variables shall be True to execute this (time consuming) step. Set `do_extraction = False` and `do_pairing = False` to skip processing and read already computed information from `certificate_data_complete.json`. 
 7. Optional: if info extracted from protection profiles is available, copy `pp_data_complete_processed.json` file into folder with results generated 
 8. Run `process_certificates.py` with `do_processing = True` to run various heuristics which will create post-processed section `processed` for every certificate (results are stored in `certificate_data_complete_processed.json`).
 9. Run `process_certificates.py` with `do_analysis = True` to perform analysis of certificates (various graphs, statistics...). If `do_analysis_filtered = True` then same analysis for subsets of certificates is performed.  
 10. Open, look and enjoy graphs like `num_certs_in_years.png` or `num_certs_eal_in_years.png`. For `certid_graph.dot.pdf` and other large graphs use Chrome to display as Adobe Acrobat Reader will fail to show whole graph. 
 
## Downloading again failes which failed to download properly

Steps:
 1. Run `search_certificate.py` to generate download script `download_failed_certs.bat` for newly added certificates
 2. Run `download_failed_certs.bat` to dowload failed/corrupted files again  
 3. Continue from step 5. 

## Updating for the newly issued certificates
 1. Run `search_certificate.py` to generate download scripts (download_cc_web.bat, download_cc_web.sh)
 2. Run `download_cc_web.bat` to download important files from Common Criteria website (requires `curl` installed)
 3. Run `search_certificate.py` with do_complete_extraction = False
 4. 


## Extending the analysis

The analysis can be extended in several ways:
 1. Additional keywords can be extracted from PDF files (modify `cert_rules.py`)
 2. Data from `certificate_data_complete.json` can be analyzed in novel way - this is why this project was concieved at first place
 3. Help to fix problems in data extraction - some PDF files are corrupted, there are many typos even in certificates identificators...
