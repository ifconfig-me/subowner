# subowner

SubOwner - A Simple tool check for subdomain takeovers. This tool is designed to check for subdomain takeovers by resolving the CNAME records and verifying them against known vulnerable services. If a subdomain is found to be vulnerable, it saves the vulnerable URL in a file.

![image](https://github.com/user-attachments/assets/ad8ec556-1707-4a23-b940-9065e33493c9)

## Features

- Supports multiple services for takeover (AWS S3, GitHub Pages, Heroku, Shopify, etc.).
- Performs CNAME resolution and service-specific checks.
- Outputs vulnerable subdomains to a file.

