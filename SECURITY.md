# Security Policy

This repository is a private CI control plane. Do not commit signing certificates, provisioning profiles, passwords, Apple credentials, GitHub personal access tokens, SignTools shared keys, IPA payloads, or customer data.

## Secrets

Runtime builder secrets must be stored in GitHub Actions Secrets only:

- `SECRET_URL`
- `SECRET_KEY`

The GitHub token used by the SignTools web service to dispatch this workflow must be stored in the service's backend secret store and restricted to this repository with the minimum Actions/workflow permissions required.

## Supply chain

The workflow checks out `SignTools/SignTools-CI` at the pinned commit recorded in the workflow. Update the pin only after reviewing the upstream diff.

## Distribution

Only sign applications and profiles you are authorized to use and distribute. Do not use this builder to bypass Apple entitlement, subscription, or authorization controls.
