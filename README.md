# OSINT Certificate Transparency Search

Searches for domain names based on several CT (Certificate Transparency) sources:
-   [Facebook](https://developers.facebook.com/tools/ct/search/)
-   [crt.sh](https://crt.sh/)

## Requirements

Install Python dependencies

`pip3 install -r requirements.txt`

-   Facebook access_token: https://developers.facebook.com/tools/accesstoken/
    Set it as environment variable: `FB_ACCESS_TOKEN`

## Usage

```
Usage: ./osintct.py -d|--domain DOMAIN [-r|--resolve] [-o|--output FILENAME]
--domain: domain name to check for (use TLD)
--resolve: try resolving IP addresses for subdomains found (can take some time)
--output: output file (CSV format) - default: output.csv
```
