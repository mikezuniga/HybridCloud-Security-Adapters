# Docker Image Scanning Adapter
This tool is for adapting (clair-based) docker image scanning process.  

Usage: python clean_docker_scan.py MINIMUM_SEVERITY SCANNER_URL STORAGE_URL  
MINIMUM_SEVERITY: Vulnerabilities with minimum severity or above need to be included in the report  
SCANNER_URL: Where your scanner (clair) is located (whole url is needed, including port)  
STORAGE URL: Where your docker images (layers) are stored  
