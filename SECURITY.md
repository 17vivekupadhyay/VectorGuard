# Security Policy

VectorGuard is a defensive security testing tool for LLM and RAG applications.

## Reporting Security Issues

If you discover a vulnerability in VectorGuard itself, please do not open a public issue with exploit details.

Instead, contact the maintainer privately:

viveku004@gmail.com
vupadhya@uwaterloo.ca

Please include:

- A description of the issue
- Steps to reproduce
- Impact
- Suggested fix, if available

## Secrets

Do not commit:

- API keys
- Access tokens
- Real prompts
- Customer data
- Internal documents
- Credentials

Use fake canary values in examples and tests.

## Intended Use

VectorGuard is intended for authorized testing only.

Do not use VectorGuard to test systems you do not own or do not have permission to assess.

## Supported Versions

VectorGuard is an early open-source project. Security fixes should target the latest public version unless otherwise noted.

## Responsible Disclosure

Please give the maintainer reasonable time to investigate and patch reported issues before public disclosure.
