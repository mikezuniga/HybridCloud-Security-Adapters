# Docker Image Scanning Adapter
This tool is for adapting (clair-based) docker image scanning process.  

Usage1: python clean_docker_scan.py MINIMUM_SEVERITY SCANNER_URL STORAGE_URL  
MINIMUM_SEVERITY: Vulnerabilities with minimum severity or above need to be included in the report  
SCANNER_URL: Where your scanner (clair) is located (whole url is needed, including port)  
STORAGE URL: Where your docker images (layers) are stored  

In addition to scan the whole repo, you can also scan individual images. 
Use the following command for this purpose:

Usage2: python push_report.py ImageID MINIMUM_SEVERITY
MINIMUM_SEVERITY: Vulnerabilities with minimum severity or above need to be included in the report  
ImageID: IDs of target images whoes report needs to be pushed into security monkey. 
