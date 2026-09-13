# Security policy

Tesra is security software, so vulnerability reports take priority over everything else.

## Report a vulnerability

Report privately through GitHub: **[open a private security advisory](https://github.com/TesfamichaelA-code/tesra/security/advisories/new)**. Please don't open a public issue, pull request or discussion.

Include what you can:

- the affected crate, npm package or registry component, and its version or commit
- the OWASP ASVS requirement involved, if you know it
- steps to reproduce, and the impact

## What happens next

| Step | Target |
|---|---|
| Acknowledge the report | Within 3 business days |
| Initial assessment | Within 7 days |
| Fix or mitigation for critical and high severity | Within 30 days |

Once a fix is released, we publish a GitHub security advisory, plus a RustSec advisory for affected crates. You get credit unless you ask not to.

## Supported versions

Tesra has no releases yet. From 1.0 onward, the latest minor release receives security fixes.

## Scope

In scope: everything in this repository, including Rust crates, npm packages, registry components and CI workflows.

Out of scope:

- issues in applications built with Tesra that come from configuration outside the kit's documented defaults
- vulnerabilities in third-party dependencies with no demonstrated impact on Tesra (please report those upstream)
