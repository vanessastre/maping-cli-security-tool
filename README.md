<p>
  <img src="main\resources\maping_logo.png" alt="mAPIng Logo">
</p>

mAPIng is a command-line interface (CLI) tool designed to evaluate the security of web applications.

Its interface allows users to request complete or specific analyses using flags.

It focuses on two main areas of checking: headers and transport layer security certificates.

## Main Features

- Analysis of HTTP headers, including X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, and Content-Type.
- Evaluation of SSL/TLS certificates, checking key strength, hashing algorithm, wildcard certificates issuance, and Let’s Encrypt validity.

## Installation

1. Clone this repository to your local machine.
2. Ensure you have Python 3 installed on your system.
3. Install the dependencies using pip:

```
pip install -r requirements.txt
```

## Usage

```
python maping.py -u <URL> [-e] [-c]
```

- `-u, --url`: Specifies the URL you want to analyze.
- `-e, --headers`: Displays detailed information about the HTTP headers of the URL (optional).
- `-c, --certificate`: Displays detailed information about the SSL certificate of the URL (optional).

### Usage Example

By default, both header and certificate analyses are executed. If you want to run only one of them, you can use the corresponding flag.

Example usage to perform both header and certificate analyses:

```
python maping.py -u https://example.com
```

Example usage to perform only header analysis:

```
python maping.py -u https://example.com -e
```

Example usage to perform only certificate analysis:

```
python maping.py -u https://example.com -c
```

## Credits

Created by Vanessa Sastre.

## License

This project is licensed under the [Attribution-NonCommercial-ShareAlike 3.0 Spain License by Creative Commons](LICENSE).

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=vanessastre_maping-cli-security-tool)](https://sonarcloud.io/summary/new_code?id=vanessastre_maping-cli-security-tool)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=vanessastre_maping-cli-security-tool&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=vanessastre_maping-cli-security-tool)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=vanessastre_maping-cli-security-tool&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=vanessastre_maping-cli-security-tool)
[![Build](https://github.com/vanessastre/maping-cli-security-tool/actions/workflows/sonarcloud.yml/badge.svg?branch=main)](https://github.com/vanessastre/maping-cli-security-tool/actions/workflows/sonarcloud.yml)

