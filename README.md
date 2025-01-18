# AzureSASHunter

⚠️ **IMPORTANT: Educational & Research Purposes Only** ⚠️

This tool is designed **strictly for educational purposes and security research**. It helps security professionals and cloud developers understand the risks of exposing Azure Storage SAS tokens in public repositories. Do not use this tool for any malicious purposes.

## Overview

The Azure Blob Storage SAS Token Scanner is a security research tool that searches GitHub repositories for potentially exposed Azure Storage SAS (Shared Access Signature) tokens. It helps:

- Demonstrate the importance of secure token management
- Research common patterns of accidental token exposure
- Educate developers about security best practices

## Prerequisites

- Python 3.7+
- GitHub Personal Access Token
- Required Python packages (see `requirements.txt`)

## Installation

1. Clone this repository (for research purposes only):

```bash
git clone https://github.com/rajeshdevopsaws/AzureSASHunter.git
cd AzureSASHunter
```

2. Install the required Python packages:

```bash
pip install -r requirements.txt
```
3. Set the GitHub Personal Access Token:

Linux/MacOS
```bash 
export GITHUB_TOKEN='your-github-token'
```

Windows (PowerShell)
```bash
$env:GITHUB_TOKEN='your-github-token'
```

4. Run the tool:

```bash
python AzureSASHunter_scan.py
```


The tool will:
1. Search GitHub for potential SAS token patterns
2. Analyze findings for token validity
3. Generate a detailed report (`sas_scan_report_<timestamp>.txt`)
4. Create a log file (`sas_scan.log`)

## Ethical Guidelines

- Use this tool responsibly and ethically
- Do not attempt to use any discovered tokens
- Report security issues to repository owners
- Follow responsible disclosure practices
- Respect GitHub's terms of service and rate limits

## Legal Disclaimer

This tool is provided for educational and research purposes only. Users are responsible for ensuring their use complies with:
- GitHub's Terms of Service
- Applicable laws and regulations
- Ethical security research practices

The authors are not responsible for any misuse or damage caused by this tool.

## Security Best Practices

When working with Azure Storage SAS tokens:
- Never commit tokens to source control
- Use Azure Key Vault for token storage
- Implement proper secret rotation
- Use time-limited tokens
- Apply principle of least privilege
- Monitor for token exposure

## Contributing

For educational and research contributions:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description
4. Ensure code follows ethical guidelines

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Acknowledgments

This tool was created to promote security awareness and education in cloud development. Special thanks to the security research community for promoting responsible disclosure and ethical practices.
