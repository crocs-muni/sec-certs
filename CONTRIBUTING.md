## Contributing

You contribution is warmly welcomed. You can help by:

 0. Spread the word about this project, look at generated processed webpages
 1. Trying the tool and reporting issues and suggestions for improvement (open Github issue)
 2. Add new regular expressions to extract relevant information from certificates (update cert_rules.py) 
 3. Perform additional analysis with extracted data (analyze_certificates.py)
 3. Improve the code (TODO: Follow Github contribution guidelines, ideally contact us first about your plan)

## Branches

- `dev` is the default branch against which all pull requests are to be made. 
- `master` is protected branch where stable releases reside. Each push or PR to master should be properly tagged by [semantic version](https://semver.org/) as it will invoke actions to publish docker image and PyPi package. 