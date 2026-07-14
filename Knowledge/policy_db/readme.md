# HTB Policy Database

This directory contains official Hack The Box policy and legal documents used by the APEX PolicyAdvisor.

## Purpose

The PolicyAdvisor retrieves information from these documents before approving or denying potentially sensitive actions such as:

- Target validation
- Scope verification
- Exploit authorization
- Brute-force checks
- Publication restrictions
- AI usage restrictions
- General HTB Terms of Service compliance

## Directory Structure

sources/
    Original Hack The Box documents.

compiled/
    Machine-readable policy files generated from the source documents and used by APEX.

## Source Documents

The documents in `sources/` are downloaded directly from the official Hack The Box website and should not be manually modified.

When Hack The Box updates a policy, replace the corresponding source document and regenerate the compiled policy database.

## Supported Sources

- Hack The Box Platform Rules
- Terms of Service
- Acceptable Use Policy
- User Agreement
- Privacy and Security documents
- Reward Program Terms
- Other official HTB legal documents