# Understanding automated analysis (heuristics)

Besides the data published by the certification bodies, *sec-certs* derives additional data about every certificate: which product it maps to in [NVD](https://nvd.nist.gov), which CVEs concern that product, which other certificates it references, which assurance requirements it claims, and so on. All of this lives in the `heuristics` attribute of a certificate object and is shown in the *Automated analysis* section of a certificate on [sec-certs.org](https://sec-certs.org), next to the official data.

```{important}
Nothing in `heuristics` comes from a certification body. Our tool *infers* it from certificate metadata, from the text of the certification artifacts and from supplementary datasets (such as CVEs). Some of it is exact, some of it is fuzzy matched. This page describes how each attribute is computed, so you can judge how far to trust it.
```

## What is derived

::::{tab-set}

:::{tab-item} Common Criteria / EUCC
| Attribute | What it is |
| --- | --- |
| `cert_id` | Normalized, canonical certificate identifier (e.g. `BSI-DSZ-CC-0782-V5-2020`) |
| `extracted_versions` | Product version(s) parsed out of the certificate name |
| `cpe_matches` | NVD CPE identifiers of the certified product |
| `related_cves` | CVEs affecting the matched CPEs |
| `direct_transitive_cves`, `indirect_transitive_cves` | CVEs reaching this certificate through the reference graph |
| `report_references`, `st_references` | Certificates referenced from the certification report / security target, and the reverse direction, both direct and transitive |
| `extracted_sars` | Security assurance requirements (SARs) claimed by the certificate |
| `eal` | Evaluation assurance level |
| `protection_profiles` | Protection profiles the certificate was evaluated against |
| `cert_lab` | Evaluation laboratory |
| `scheme_data` | The matching entry from the national scheme website |
:::

:::{tab-item} FIPS 140
| Attribute | What it is |
| --- | --- |
| `algorithms` | Approved algorithms of the module (from the CMVP page and from tables in the security policy) |
| `extracted_versions` | Version(s) parsed out of module name and HW/FW version fields |
| `cpe_matches` | NVD CPE identifiers of the certified module |
| `related_cves` | CVEs affecting the matched CPEs |
| `module_processed_references` | Certificates referenced from the CMVP module page (caveat field), and the reverse direction |
| `policy_processed_references` | Certificates referenced from the security policy PDF, and the reverse direction |
| `direct_transitive_cves`, `indirect_transitive_cves` | CVEs reaching this certificate through the reference graph |
:::
::::

## How it is computed

Each attribute is produced by one step of a pipeline that runs over the whole dataset. The steps below run in the order in which they are listed, and some of them consume what the previous ones produced. This chaining is the main thing to keep in mind when you judge the result. An error early on propagates downstream, so a wrongly assigned `cert_id` misplaces the certificate in the reference graph, and the wrong reference graph then hands it somebody else's transitive CVEs.

Not every step runs for every framework. The headings say which ones each step applies to.

The whole chain is recomputed from scratch on every run of the full pipeline, since the steps depend on the dataset as a whole and on external data. The derived data of a certificate can therefore change between two snapshots even when the certificate itself stayed the same, because other certificates entered the dataset or because NVD or a scheme website changed.

### Protection profiles (CC, EUCC)

`protection_profiles` is an exact lookup of the protection profile links published with the certificate against our protection profile dataset. The result is used again at the very end of the chain, where it serves as the fallback for the EAL.

The ENISA source we scrape for EUCC publishes no protection profile links, so this attribute stays empty for EUCC certificates, and the EAL fallback that depends on it never fires for them.

### Module algorithms (FIPS)

`algorithms` combines two sources: the approved algorithms listed on the CMVP module page, and algorithms extracted from tables inside the security policy PDF. The table extraction runs on heterogeneous PDFs, so it both misses entries and picks up noise. These numbers matter beyond the attribute itself, because the reference step below uses them to tell algorithm certificate numbers apart from module numbers.

### Product versions and CPE matches (CC, EUCC, FIPS)

`extracted_versions` comes from a regex cascade over the product name (and, for FIPS, over the HW/FW version fields): first `X.Y[.Z]`/`vX.Y`/`version X.Y` patterns, then any standalone number, then a `-` placeholder. Its purpose is to widen the pool of CPE candidates, so it errs heavily on the side of extracting too much.

**CPE matching** (`sec_certs.model.cpe_matching.CPEClassifier`) runs per certificate:

1. The manufacturer string is mapped to candidate CPE *vendors* using exact hits, leading-token combinations, comma/slash splits and a handful of hand-written aliases (`hewlett packard` → `hp`, `stmicroelectronics` → `st`, …).
2. Only CPEs of those vendors are kept, and among them only the ones whose version is compatible with `extracted_versions`. What remains is filtered by platform (Windows/Linux/macOS/Android/iOS) and by service pack / release number.
3. Each candidate is scored against the (lemmatized) product name with several `rapidfuzz` string similarities, taking the maximum.
4. Candidates scoring at or above `cpe_matching_threshold` are kept, at most `cpe_n_max_matches` of them.
5. If nothing matched, the matcher retries with relaxed settings. It first also scores the CPE item name and reconstructs a title for CPE entries that have none, still at `cpe_matching_threshold`, and then retries against CPE entries with an unspecified version, where only a perfect score of 100 counts.

Very weak CPE entries are excluded from the pool up front: entries with no digit anywhere and an unspecified version, entries whose item name is three characters or shorter, release candidates, and a couple of hand-listed generic Windows entries.

### CVEs of the matched products (CC, EUCC, FIPS)

For every CPE matched in the previous step, `related_cves` takes the CVEs that NVD marks as applicable, both directly and through NVD *criteria configurations* (the AND-ed "running on/with" combinations). No fuzzy matching happens here, so all of the uncertainty in this attribute is inherited from the CPE matching above.

### Certificate identifiers (CC)

The source data of a Common Criteria certificate contains no single machine-readable identifier, so we reconstruct one from four independent sources, weigh the candidates they produce and pick the best one. Each source normalizes its own candidates by their number of occurrences and multiplies them by its weight, and the results are summed per candidate. The metadata, keyword and file name sources look at both the report and the certificate, so a candidate confirmed in both documents can outscore one that only the front page proposes.

| Source | Weight |
| --- | --- |
| Certificate ID on the report front page (scheme-specific parsers) | 1.5 |
| PDF metadata (`/Title`, `/Subject`) of report and certificate | 1.2 |
| Keyword matches in the text of report and certificate | 1.0 |
| Report / certificate file name | 1.0 |

Every candidate is *canonicalized* first. Eighteen schemes have a function that rebuilds one canonical ID out of the parsed components, so that the variants of `BSI-DSZ-CC-0782-V5-2020` collapse into a single identifier; for the remaining schemes canonicalization only cleans up whitespace and hyphens. Candidates that cannot be canonicalized are dropped, the highest-scoring candidate wins, and ties are broken in favour of the more specific (longer) identifier.

EUCC and FIPS certificates skip the reconstruction, since both frameworks publish a usable identifier of their own.

### References between certificates (CC, EUCC, FIPS)

References are built by looking for the canonical certificate identifiers from the previous step. For CC/EUCC we build two separate graphs, one from the certification report and one from the security target. For FIPS we build one from the caveat field of the CMVP page and one from the security policy PDF. Each graph gives four sets per certificate: `directly_referencing`, `indirectly_referencing`, `directly_referenced_by` and `indirectly_referenced_by`, where the indirect variants are the transitive closure. References to certificates outside the dataset are dropped.

For FIPS, candidate identifiers are pruned before the graph is built. We discard the certificate's own number, numbers at or below `always_false_positive_fips_cert_id_threshold`, numbers that coincide with an algorithm certificate number of the same module, and numbers that the keyword rules already recognised as certificate-like references to something other than a module. A bare `#1234` in a security policy is more often an algorithm than a module.

```{note}
The reference graph records the fact that one certificate mentions another. It says nothing about the reason for the mention (component reuse, re-evaluation of a previous version, …). Inferring that meaning is an experimental model that runs outside the pipeline, see [inferring inter-certificate reference context](user_guide.md#inferring-inter-certificate-reference-context).
```

### Transitive CVEs (CC, EUCC, FIPS)

This step is where two branches of the chain meet: it propagates the CVEs computed earlier along the reference graph just built. Only one graph per framework feeds it, the report graph for CC and EUCC and the security policy graph for FIPS, so what a security target or a CMVP module page mentions does not propagate. `direct_transitive_cves` collects the `related_cves` of the certificates that directly reference this one, and `indirect_transitive_cves` does the same over the transitive closure. Certificates that share a `cert_id` with another certificate are left out of this step entirely, see the general notes below.

### Scheme data (CC, EUCC)

National scheme websites publish data that the Common Criteria portal lacks, such as the evaluation facility, the expiry date or richer descriptions. `scheme_data` links a portal certificate to its entry on the scheme website. Every candidate pair is scored, then matches are assigned greedily and one-to-one above `cc_matching_threshold`. The score stays exact where it can: an equal canonical `cert_id` scores 100, an exact product-and-vendor match 99, an identical report PDF 95, an identical security target PDF 93. Only below that do we fall back to a weighted fuzzy blend of product name, vendor, identifier, certification date and assurance level.

A related matcher for FIPS, `FIPSProcessMatcher`, links Implementation Under Test (IUT) and Modules In Process (MIP) entries to the certificates that eventually resulted from them. It scores product name and vendor only, with an exact match on both scoring 99, and it is not part of the pipeline: nothing writes its output into `heuristics`, it is there for analyses such as the [in-process notebook](https://github.com/crocs-muni/sec-certs/blob/main/notebooks/fips/in_process.ipynb).

### Evaluation laboratory (CC, EUCC)

`cert_lab` comes from the front page parsers, and only the five schemes that have one (ANSSI, BSI, NSCIB, NIAP, Canada) produce a value at all. The French and Dutch parsers read an actual laboratory from the page, while the German, American and Canadian ones write a fixed label for the scheme itself. The value is a list, and each entry is cut down to its first word in upper case, so a NIAP certificate ends up with `US` rather than a laboratory name.

### EAL and SARs (CC, EUCC)

These two run last, and the EAL closes the loop back to the first step. `eal` is read from the `security_level` field of the certificate, an `EAL1` to `EAL7`, possibly augmented with extra requirements and then written as `EAL4+`. If the field carries no EAL, we fall back to the lowest EAL among the protection profiles linked at the beginning of the chain.

`extracted_sars` merges three sources in decreasing priority: the `security_level` field, keyword matches in the security target, and keyword matches in the certification report. The first source to claim a SAR family such as `ADV_FSP` wins, and conflicting claims from later sources are discarded. Within one document, the highest level found for a family wins. Next to the attribute, certificates carry an `actual_sars` property, which combines the SARs implied by the EAL with the extracted ones.

## How reliable it is

Reliability follows from how each attribute is computed. Only a handful of them are exact. The rest are fuzzy matches, or they depend on a previous step.

**Exact:**

- `protection_profiles` is looked up by exact equality on the profile links published with the certificate.
- `eal` and `extracted_sars` are exact as far as they come from the `security_level` field, which is source data. Where they come from the documents instead, they belong to the group below.

Values in this group can be missing, for example when no profile link was published, but a value that is present was not guessed.

**Fuzzy, or dependent on a different step**. Everything else:

- `extracted_versions` and `cpe_matches` are string matches against NVD. `related_cves` is an exact database join on top of them, which makes it exactly as good as the CPE match underneath it. A product with no match therefore has no CVEs listed, which says nothing about whether it is affected.
- CC `cert_id` is voted on by four sources that usually agree. When they disagree the heaviest one wins, so a misparsed front page can override three sources that were right, and a certificate whose documents yield no candidate at all ends up with no identifier.
- The reference graphs record identifier-looking strings found in a document, so any mention counts the same as a real dependency. They are also limited by the correct `cert_id` assignment that feeds them.
- Transitive CVEs combine the reference graph with `related_cves` and inherit the errors of both.
- `scheme_data` is assigned by a score. The top of the score ladder is an identical report PDF or an equal `cert_id`, but the score is not stored with the match, so a value on its own does not tell you which case produced it. Where it was the identifier, it is only as good as CC `cert_id`.
- `cert_lab` and the SARs extracted from documents are parsed out of the converted PDF text, the first by the scheme-specific front page parsers, the second by the keyword rules.
- FIPS `algorithms` merges entries parsed from the CMVP module page with numbers pulled out of tables in the security policy PDF. The page side is structured, though the certificate references inside it are still picked up by a regular expression over the cell text. The policy tables are worse, the extraction there both misses entries and picks up noise. The merged set does not record which side an entry came from, but `pdf_data.module_algorithms` and `pdf_data.policy_algorithms` keep the two apart.
- The `eal` fallback, used when `security_level` carries no EAL, is only as good as the protection profile linking.

**General notes:**

- The derived data describes the product as it is named, and the certified configuration is usually narrower. A CVE matched to a product can concern a version or a feature that was never part of the evaluation, and the evaluated configuration can be hit by a vulnerability that NVD files under a different CPE.
- Anything derived from document text depends on the PDF to text conversion. Badly converted documents give us almost nothing to match on.
- The reference graph is relative to the snapshot it was computed on. References to certificates that are not in the dataset get dropped, and a certificate that enters the dataset later can change the transitive references of the ones already there.
- Two certificates can end up with the same `cert_id`. Only one of them (the one with the lower digest) takes part in the reference graph and the others come out with no references, while transitive CVEs are skipped for all of them, the one in the graph included.
- The thresholds and the PDF converter are configurable. Running the pipeline with other settings gives different results, see [configuration](configuration.md).

## How to verify and evaluate it

### Tracing a single certificate

A suspicious result can usually be traced back to what produced it. The matching scores themselves are not kept, but the evidence is: the keyword hits, front page parses and PDF metadata that the steps consumed all stay in `pdf_data`, and the converted text should be in the dataset directories. Say a certificate references another one and you want to see where that came from:

```python
cert = dset["11f77cb31b931a57"]

cert.heuristics.cert_id                       # 'BSI-DSZ-CC-0874-2014'
cert.heuristics.report_references.directly_referencing
                                              # {'BSI-DSZ-CC-0788-2012'}

# where the reference came from: identifier matches in the report text,
# per scheme, with the number of occurrences
cert.pdf_data.report_keywords["cc_cert_id"]   # e.g. {'DE': {'BSI-DSZ-CC-0788-2012': 3}}

# the other evidence behind cert_id
cert.pdf_data.report_frontpage                # what the front page parser read
cert.pdf_data.report_metadata                 # /Title and /Subject of the PDF

# and the text everything was matched against
cert.state.report.txt_path
```

The same approach works for the other attributes.

### Evaluating a whole attribute

To judge an attribute over the whole dataset instead of one certificate, the repository has a few example notebooks that can be re-run against the current data:

- [`cpe_eval.ipynb`](https://github.com/crocs-muni/sec-certs/blob/main/notebooks/cc/cpe_eval.ipynb) prepares a random sample of CPE matches for manual labeling in Label Studio and reports how many of them were correct.
- [`cert_id_eval.ipynb`](https://github.com/crocs-muni/sec-certs/blob/main/notebooks/cc/cert_id_eval.ipynb) looks at certificates with no identifier and at duplicate identifier assignments, separating out those caused by the portal publishing the same report for several certificates, and compares identifiers and references against a manually assigned ground truth.
- [`scheme_eval.ipynb`](https://github.com/crocs-muni/sec-certs/blob/main/notebooks/cc/scheme_eval.ipynb) reports scheme matching rates and how they change with the threshold.

They are also a starting point for measuring something we have not, such as how often a certificate that has a CPE in NVD ends up with no match at all.

## How to use the data

Derived data lives in the `heuristics` attribute of a certificate. In Python it is an object with the attributes listed at the top of this page.

```python
from sec_certs.dataset.fips import FIPSDataset

dset = FIPSDataset.from_web()
cert = dset["5f0fbfc126a9876e"]

cert.heuristics.cpe_matches        # set of CPE URIs
cert.heuristics.related_cves       # set of CVE ids

```
