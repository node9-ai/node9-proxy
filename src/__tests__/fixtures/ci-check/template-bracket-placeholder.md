# Package Investigation Report

## Package Metadata
- **Package Name**:
- **Registry**: [NPM / PyPI / RubyGems / etc.]
- **Affected Versions**:

## Indicators of Compromise
- **Malicious URL(s)**:
- **Exfiltrated Data Types**: [Environment variables, ~/.ssh/id_rsa, /etc/shadow, etc.]
- **Exfiltration Method**: [DNS tunneling, HTTP POST to C2, etc.]

## Analysis Summary
- **Primary Mechanism**: [Typosquatting / Dependency Confusion / Maintainer Takeover]
- **Behavior Description**:
  - [Example: Installs a postinstall script that sends environment variables out.]

## Recommended Mitigations
1. [ ] Report the package to the registry.
2. [ ] Rotate secrets the package could read.
