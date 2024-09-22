# subowner

SubOwner - A Simple tool check for subdomain takeovers. This tool is designed to check for subdomain takeovers by resolving the CNAME records and verifying them against known vulnerable services. If a subdomain is found to be vulnerable, it saves the vulnerable URL in a file.

## Disclaimer

> [!WARNING]  
> This tool is intended only for educational purposes and for testing in authorized environments. https://twitter.com/nav1n0x/ and https://github.com/ifconfig-me take no responsibility for the misuse of this code. Use it at your own risk. Do not attack a target you don't have permission to engage with. This tool uses the publicly released payloads and methods. 


![image](https://github.com/user-attachments/assets/bd3a0f26-4551-45db-9f69-022a9421e581)


## Features

- Supports multiple services for takeover (AWS S3, GitHub Pages, Heroku, Shopify, etc.).
- Performs CNAME resolution and service-specific checks.
- Outputs vulnerable subdomains to a file.

