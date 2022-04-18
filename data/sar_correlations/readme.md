## Correlations between SARs and CVEs

- Dataframes (in csv) with Pearson's correlation coefficient between [CC SARs](https://www.commoncriteriaportal.org/files/ccfiles/CCPART1V3.1R5.pdf) and two variables: `(n_cves, worst_cve)`.
- In the first row, correlation between `EAL` and `(n_cves, worst_cve)` is displayed.
- Collumn `support` shows number of rows with non-zero entry in the correlated column.
- `all_certs_sar_cve_corr.csv` computes correlations on all certificates
- `vuln_rich_certs_sar_cve_corr.csv` computes correlations only on the certificates with `>0` vulnerabilities.
- The csvs only show rows where one of the values is not `NaN` (due to missing data).
- Empty cell means that the value is `NaN` due to missing data and correlation is meaningless.