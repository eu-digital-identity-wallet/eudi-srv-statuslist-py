# eudi-srv-statuslist-py

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

*A Python-based revocation project for Attestation Status List and Attestation Revocation List.*

## Description
`statuslist-py` is a Python library designed to issue and manage revocation status using Attestation Status Lists and Attestation Revocation Lists.

## Installation
Refer to the [installation guide](./install.md) for setup instructions.

## Usage
Detailed API documentation and usage examples can be found in the [Swagger UI](https://dev.issuer.eudiw.dev/tslswagger/swagger).
`/take`, `/set` and their `/batch` variants need the `X-Api-Key` header set to the configured `api_key`
(401 `{"message": "Unauthorized access"}` otherwise). `/get` is not authenticated.
The signed lists are served, unauthenticated, at the URIs `/take` returns (see [install.md](./install.md#5-serving-the-lists)).

The service is configured through a YAML file: see [app/config_statuslist_example.yaml](app/config_statuslist_example.yaml).

## Features
- Supports Attestation Status List (ASL) [draft-ietf-oauth-status-list-12](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-12)
- Supports Attestation Revocation List (ARL) [ ISO/IEC CD 18013-5 second edition ]

## Tests

```shell
pip install -r requirements-dev.txt
env $(grep -v '^#' .env.test | xargs) pytest --cov=app --cov-config=pyproject.toml
```

CI (`.github/workflows/sonar.yml`) runs the same command and fails below 80% coverage.

## :heavy_exclamation_mark: Disclaimer

The released software is a initial development release version:

-   The initial development release is an early endeavor reflecting the efforts of a short timeboxed
    period, and by no means can be considered as the final product.
-   The initial development release may be changed substantially over time, might introduce new
    features but also may change or remove existing ones, potentially breaking compatibility with your
    existing code.
-   The initial development release is limited in functional scope.
-   The initial development release may contain errors or design flaws and other problems that could
    cause system or other failures and data loss.
-   The initial development release has reduced security, privacy, availability, and reliability
    standards relative to future releases. This could make the software slower, less reliable, or more
    vulnerable to attacks than mature software.
-   The initial development release is not yet comprehensively documented.
-   Users of the software must perform sufficient engineering and additional testing in order to
    properly evaluate their application and determine whether any of the open-sourced components is
    suitable for use in that application.
-   We strongly recommend not putting this version of the software into production use.
-   Only the latest version of the software will be supported

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
