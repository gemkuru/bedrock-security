# Security Policy

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Email**: security@bedrocklens.com

**Please include:**
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

### Scope

**In Scope:**
- Authentication/authorization bypasses
- Encryption weaknesses
- Data exposure vulnerabilities
- Rate limiting bypasses
- Input validation failures

**Out of Scope:**
- Social engineering attacks
- Physical access attacks
- Denial of service (volumetric)
- Issues in dependencies (report to upstream)

### Safe Harbor

We will not pursue legal action against researchers who:
- Make good faith efforts to avoid privacy violations
- Do not access or modify other users' data
- Report vulnerabilities promptly
- Do not publicly disclose before we've had time to fix

### Recognition

With your permission, we'll acknowledge your contribution in:
- Our security changelog
- This repository's contributors

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < 1.0   | No        |

## Security Best Practices

When using this code:

1. **Never commit encryption keys** - Use environment variables
2. **Rotate keys periodically** - Especially after any suspected compromise
3. **Use HTTPS everywhere** - Encryption is meaningless over HTTP
4. **Monitor rate limit logs** - Watch for abuse patterns
5. **Keep dependencies updated** - Web Crypto API vulnerabilities are rare but serious

## Changelog

Security-related changes will be documented here.

| Date | Description |
|------|-------------|
| 2024-01 | Initial public release |
