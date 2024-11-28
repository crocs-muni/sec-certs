# Search examples

The goal is to provide a curated catalog of search strings over Common Criteria and FIPS-140
certification artifacts executed on the [sec-certs](https://sec-certs.org) webpage.


| {fas}`people-group`    | You are encouraged to contribute - please create a pull request and insert an entry into a suitable section **lexicographically**. Thank you! |
|------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------|

The sec-certs started in 2019 with the goal of providing automatic processing of certification artifacts.
The extensive collection of keyword search regex strings is already included by the project in
[rules.yml](https://github.com/crocs-muni/sec-certs/blob/main/src/sec_certs/rules.yaml) file.
Custom full text and title-only searches are additionally possible via the web interface.
This document provides a list of read-to-use *aggregated* search strings for different domains
using [Whoosh query language](https://whoosh.readthedocs.io/en/latest/querylang.html).
If you will find this list helpful, please consider citing our work as:
```latex
@article{sec-certs,
	title = {sec-certs: Examining the security certification practice for better vulnerability mitigation},
	journal = {Computers & Security},
	volume = {143},
	year = {2024},
	issn = {0167-4048},
	doi = {10.1016/j.cose.2024.103895},
	url = {https://www.sciencedirect.com/science/article/pii/S0167404824001974},
	author = {Adam Janovsky and Jan Jancar and Petr Svenda and Łukasz Chmielewski and Jiri Michalik and Vashek Matyas},
	keywords = {Security certification, Common criteria, Vulnerability assessment, Data analysis, Smartcards}
}
```

### Format and notation
> **Search string goal: Common Criteria** (hyperlinked to search on sec-certs.org page) **( {fas}`network-wired` )**(result of search visualized in graph of references)**, FIPS-140  ( {fas}`network-wired` )**
> <br>
> `whole search string` (for manual cut&paste)
> <br>
> Short description of search string targeted domain, expected results and interpretation.

````{warning}
False positives may be present, always check the actual certification document as
search hit may still be 'out of ToE scope', with 'no security functionality claimed' etc.
````
   
---

## Cryptographic capabilities

### Multi-party security
- Multi-party security use: [Common Criteria](https://sec-certs.org/cc/ftsearch/?q=%22multiparty%22%20OR%20%22SMPC%22%20OR%20%22Multi-Party%22%20OR%20%22FROST%22&cat=abcdefghijklmop&status=any&type=any) ([{fas}`network-wired`](https://sec-certs.org/cc/network/?q=%22multiparty%22%20OR%20%22SMPC%22%20OR%20%22Multi-Party%22%20OR%20%22FROST%22&cat=abcdefghijklmop&status=any&type=any&search=fulltext)), [FIPS-140](https://sec-certs.org/fips/ftsearch/?q=%22multiparty%22%20OR%20%22SMPC%22%20OR%20%22Multi-Party%22%20OR%20%22FROST%22&cat=abcdef&status=Any&type=any) ([{fas}`network-wired`](https://sec-certs.org/fips/network/?q=%22multiparty%22%20OR%20%22SMPC%22%20OR%20%22Multi-Party%22%20OR%20%22FROST%22&cat=abcdef&status=Any&type=any&search=fulltext))
  <br>
 ```"multiparty" OR "SMPC" OR "Multi-Party" OR "FROST"```
  <br> 
Certificates mentioning generically any multiparty execution, hopefully in security or even cryptographic context. 


### Post-quantum cryptography
- Post-quantum algorithms support: [Common Criteria](https://sec-certs.org/cc/ftsearch/?q=%22post%20quantum%22%20OR%20%22post-quantum%22%20OR%20%22PQC%22%20OR%20%22KYBER%22%20OR%20%22SPHINCS%22%20OR%20%22NTRU%22%20OR%20%22XMSS%22%20OR%20%22LWE%22%20OR%20%22CSIDH%22%20OR%20%22BLISS%22%20OR%20%22RLCE%22%20OR%20%22McEliece%22%20OR%20%22CRYSTALS%22%20OR%20%22Dilithium%22&cat=abcdefghijklmop&status=any&type=any) ([{fas}`network-wired`](https://sec-certs.org/cc/network/?q=%22post%20quantum%22%20OR%20%22post-quantum%22%20OR%20%22PQC%22%20OR%20%22KYBER%22%20OR%20%22SPHINCS%22%20OR%20%22NTRU%22%20OR%20%22XMSS%22%20OR%20%22LWE%22%20OR%20%22CSIDH%22%20OR%20%22BLISS%22%20OR%20%22RLCE%22%20OR%20%22McEliece%22%20OR%20%22CRYSTALS%22%20OR%20%22Dilithium%22&cat=abcdefghijklmop&status=any&type=any&search=fulltext)), [FIPS-140](https://sec-certs.org/fips/ftsearch/?q=%22post%20quantum%22%20OR%20%22post-quantum%22%20OR%20%22PQC%22%20OR%20%22KYBER%22%20OR%20%22SPHINCS%22%20OR%20%22NTRU%22%20OR%20%22XMSS%22%20OR%20%22LWE%22%20OR%20%22CSIDH%22%20OR%20%22BLISS%22%20OR%20%22RLCE%22%20OR%20%22McEliece%22%20OR%20%22CRYSTALS%22%20OR%20%22Dilithium%22&cat=abcdef&status=Any&type=any) ([{fas}`network-wired`](https://sec-certs.org/fips/network/?q=%22post%20quantum%22%20OR%20%22post-quantum%22%20OR%20%22PQC%22%20OR%20%22KYBER%22%20OR%20%22SPHINCS%22%20OR%20%22NTRU%22%20OR%20%22XMSS%22%20OR%20%22LWE%22%20OR%20%22CSIDH%22%20OR%20%22BLISS%22%20OR%20%22RLCE%22%20OR%20%22McEliece%22%20OR%20%22CRYSTALS%22%20OR%20%22Dilithium%22&cat=abcdef&status=Any&type=any&search=fulltext))
  <br>
 ```"post quantum" OR "post-quantum" OR "PQC" OR "KYBER" OR "SPHINCS" OR "NTRU" OR "XMSS" OR "LWE" OR "CSIDH" OR "BLISS" OR "RLCE" OR "McEliece" OR "CRYSTALS" OR "Dilithium"```
  <br> 
Certificates mentioning post-quantum cryptographic algorithms support.

## Vulnerabilites assesment

### ROCA vulnerability
ROCA [CVE-2017-15361](https://nvd.nist.gov/vuln/detail/CVE-2017-15361) is private key recovery vulnerability present in Infineon RSALib library used by smartcard and TPM devices between roughly 2004 and 2017. More details available [here](https://crocs.fi.muni.cz/papers/rsa_ccs17). 

- ROCA-vulnerable Infineon RSALib library v1.02.013: [Common Criteria](https://sec-certs.org/cc/ftsearch/?q=%22v1.02.013%22&cat=abcdefghijklmop&status=any&type=any) ([{fas}`network-wired`](https://sec-certs.org/cc/network/?q=%22v1.02.013%22&cat=abcdefghijklmop&status=any&type=any&search=fulltext)), no FIPS-140
  <br>
 ```"v1.02.013"```
  <br> 
Certificates mentioning confirmed vulnerable version of Infineon RSALib 1.02.013 library.

- ROCA-vulnerable Infineon RSALib library and similar (wildcard) v1.02.0??: [Common Criteria](https://sec-certs.org/cc/ftsearch/?q=v1.02.0*&cat=abcdefghijklmop&status=any&type=any) ([{fas}`network-wired`](https://sec-certs.org/cc/network/?q=v1.02.0*&cat=abcdefghijklmop&status=any&type=any&search=fulltext)), no FIPS-140
  <br>
 ```v1.02.0*```
  <br> 
Certificates mentioning Infineon RSALib 1.02.013 and other similar library versions. Versions v1.02.008, v1.02.010, v1.02.014 possibly also vulnerable.

- ROCA-vulnerable (likely) Infineon RSALib libraries other than v1.02.013: [Common Criteria](https://sec-certs.org/cc/ftsearch/?q=v1.02.0*%20NOT%20%22v1.02.013%22&cat=abcdefghijklmop&status=any&type=any) ([{fas}`network-wired`](https://sec-certs.org/cc/network/?q=v1.02.0*%20NOT%20%22v1.02.013%22&cat=abcdefghijklmop&status=any&type=any&search=fulltext)), no FIPS-140
  <br>
 ```v1.02.0* NOT "v1.02.013"```
  <br> 
Certificates mentioning posibly vulnerable RSALib version other than v1.02.013. Versions v1.02.008, v1.02.010, v1.02.014 possibly also vulnerable.

- Certificate IDs from Austria report 163484: [Common Criteria](https://sec-certs.org/cc/ftsearch/?q=%22BSI-DSZ-CC-0833-2013%22%20OR%20%22BSI-DSZ-CC-0921-2014%22%20OR%20%22BSI-DSZ-CC-0782-2012%22%20OR%20%22BSI-DSZ-CC-0758-2012%22%20OR%20%22ANSSI-CC-2013%2F55%22&cat=abcdefghijklmop&status=any&type=any) ([{fas}`network-wired`](https://sec-certs.org/cc/network/?q=%22BSI-DSZ-CC-0833-2013%22%20OR%20%22BSI-DSZ-CC-0921-2014%22%20OR%20%22BSI-DSZ-CC-0782-2012%22%20OR%20%22BSI-DSZ-CC-0758-2012%22%20OR%20%22ANSSI-CC-2013%2F55%22&cat=abcdefghijklmop&status=any&type=any&search=fulltext)), no FIPS-140
  <br>
 ```"BSI-DSZ-CC-0833-2013" OR "BSI-DSZ-CC-0921-2014" OR "BSI-DSZ-CC-0782-2012" OR "BSI-DSZ-CC-0758-2012" OR "ANSSI-CC-2013/55"```
  <br> 
Certificates mentioning certificate IDs directly or indirectly mentioned in [Austria report 163484](https://archive.org/details/incident-report-id-163484-austria) related to Estonian eID platform (ANSSI-CC-2013/55).

## Unsorted
