# Research: levels, identity providers and tooling (September 2026)

Collected 2026-09-13 as a follow-up to the [baseline](2026-09-baseline.md). It covers the evidence behind decisions D-01 to D-06 in the [blueprint](../blueprint.md).

## 1. Which ASVS level to default to

From ASVS 5.0, "What is the ASVS":

- **Level 1** "contains the minimum requirements to consider when securing an application and represents a critical starting point", about 20% of requirements. Password requirements weigh most here, "as from higher levels, the multi-factor authentication requirements become relevant."
- **Level 2:** "Most applications should be striving to achieve this level of security." Complying means implementing about 70% of ASVS (all L1 and L2 requirements).
- **Level 3** "should be the goal for applications looking to demonstrate the highest levels of security", the final ~30%.
- ASVS doesn't prescribe a level: "an organization should analyze its risks and decide". Its examples: an early-stage startup collecting little sensitive data might start at L1, while a bank "may have difficulty justifying anything less than Level 3".

**Conclusion:** default to L2 and make L1 a one-line change for prototypes and low-risk apps.

## 2. Social identity providers

In Tesra's order.

| | Google | GitHub | Microsoft | Apple |
|---|---|---|---|---|
| Protocol | OpenID Connect | OAuth 2.0 only; no ID token for user sign-in | OpenID Connect (v2.0 endpoint) | OpenID Connect with Apple-specific rules |
| Issuer | `https://accounts.google.com` or `accounts.google.com`; Google documents both | None | Contains the tenant and ends in `/v2.0`. Personal Microsoft accounts use tenant `9188040d-6c67-4c5b-b112-36a304b66dad` | `https://appleid.apple.com` |
| Stable user key | `sub` ("unique to a Google Account even if the user changes their email address") | Numeric `id` from `GET /user`; the `login` name can change | `sub` (pairwise per application, immutable) or `oid`, with `tid` for routing | `sub` |
| Email | `email` with `email_verified`; `hd` present only for Google Workspace or Cloud organization accounts | `GET /user/emails`, using verified addresses only | Not guaranteed correct and mutable: "Never use it for authorization or to save data for a user" | May be a private relay address |
| PKCE | S256 (and plain) supported | S256 only, supported since 2025-07-14, not required | Supported | Check during implementation |
| Nonce | Required | No ID token | Validate against the request | Validate against the request |
| Response mode | Query | Query | Query | `form_post` is required when requesting name or email |
| Client authentication | Client secret | Client secret | Client secret or certificate | ES256-signed JWT client secret: `iss` = Team ID, `sub` = client ID, `aud` = `https://appleid.apple.com`, valid for at most 6 months |
| Name | `name` claim | `GET /user` | `name` (display only) | Sent only on the first authorization, in the `user` form field |

Microsoft's claims guidance also says never to use `email`, `preferred_username` or `unique_name` to decide access, because "these claims aren't unique and can be controllable by tenant administrators or sometimes users". It also advises against `upn`, which can change.

### What this means for Tesra

1. **GitHub isn't OpenID Connect.** ASVS V10.5 (OIDC client) doesn't apply to it, but V10.2 (OAuth client) does. The provider abstraction must support "OAuth 2.0 plus a user API" as well as OIDC. Mix-up defense (V10.2.2) comes from a separate callback URL per provider, since GitHub sends no issuer.
2. **Microsoft multi-tenant issuers are templates.** A generic exact-match issuer check fails against `common` metadata. Tesra substitutes the token's `tid` into the template, then requires an exact match, with an optional tenant allowlist.
3. **Never link accounts by email,** for any provider.
4. **Apple's `form_post` callback is a cross-site POST,** so browsers don't send `SameSite=Lax` or `Strict` cookies with it. Apple's OAuth transaction cookie needs `SameSite=None; Secure; HttpOnly`, a short lifetime and single use. The callback skips the CSRF token check (state, nonce and PKCE protect it) and 303-redirects to a same-site URL that issues the session.
5. **Apple client secrets expire within 6 months.** Signing a fresh short-lived secret for each token request removes the rotation chore.
6. **MFA claims:** Google's and Microsoft's ID token references list no `amr` claim, and GitHub issues no ID token. Unless a provider's token proves MFA, Tesra counts a social sign-in as one factor (V6.8.4). At L2 that means a passkey or TOTP step follows.

## 3. Tooling

### TypeScript 7

- `typescript@7.0.2` is the `latest` tag. It ships per-platform native binaries (`@typescript/typescript-linux-x64`, etc.). The only other stable versions in the 6.x/7.x range are 6.0.2 and 6.0.3.
- `typescript-eslint` declares `typescript: >=4.8.4 <6.1.0`, so it can't be used with TS 7 yet.
- `@storybook/react-vite@10.6.0` declares `typescript: >= 4.9.x`.
- **Decision:** type-check with TS 7 and lint with Biome, which doesn't depend on the TypeScript API.

### pnpm supply-chain settings

The current pnpm settings reference lists these in `pnpm-workspace.yaml`:

- `minimumReleaseAge` (plus `minimumReleaseAgeExclude` and `minimumReleaseAgeStrict`)
- `trustPolicy` (plus `trustPolicyExclude`)
- `blockExoticSubdeps`
- `strictDepBuilds`, `allowBuilds` and `dangerouslyAllowAllBuilds`
- `verifyStoreIntegrity` and `strictStorePkgContentCheck`

### Dependabot cooldown

Dependabot's cooldown option is generally available, with `default-days` and `semver-major-days`, `semver-minor-days` and `semver-patch-days`. Since July 2026, version updates get a 3-day cooldown by default. Security updates are exempt.

### Trusted publishing

- **crates.io** added trusted publishing in July 2025. GitHub Actions exchanges its OIDC token through `rust-lang/crates-io-auth-action` for a 30-minute publish token.
- **npm** trusted publishing with OIDC became generally available on 2025-07-31. Publishing this way generates provenance attestations automatically.

### GitHub Actions pinned for CI (latest semver tags on 2026-09-13)

| Action | Tag | Commit |
|---|---|---|
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-node | v7.0.0 | `820762786026740c76f36085b0efc47a31fe5020` |
| actions/setup-python | v7.0.0 | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| actions/upload-artifact | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| pnpm/action-setup | v6.1.0 | `ea17c68df8912ef543352723c149a84f56e3d413` |
| Swatinem/rust-cache | v2.9.2 | `6323deb102c322ba6fcbdcafc7e3dddab59af2b6` |
| taiki-e/install-action | v2.87.12 | `3f74d7c16a4242f1c95561e98edc25d36adb4375` |
| EmbarkStudios/cargo-deny-action | v2.1.1 | `3c6349835b2b7b196a839186cb8b78e02f7b5f25` |
| ossf/scorecard-action | v2.4.4 | `2d1146689b8cda280b9bc96326124645441f03bc` |
| github/codeql-action | v4.38.0 | `b96794f015dfd88f77b49b1c93e0fa7110f94c63` |
| zaproxy/action-baseline | v0.15.0 | `de8ad967d3548d44ef623df22cf95c3b0baf8b25` |
| actions/download-artifact | v8.0.1 | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |
| zizmorcore/zizmor-action | v0.6.4 | `cc914d7f3750a2d13d75c7f184a1060aa0e9d482` |
| raven-actions/actionlint | v2.2.0 | `3d39aea434753780c3b3d4a1a31c854b4dbf49d7` |

Workflow linters are pinned to zizmor 1.30.1 and actionlint 1.7.12.

### Local developer tools

| Tool | Version | How it was installed |
|---|---|---|
| cargo-nextest | 0.9.144 | GitHub release binary. No checksum is published; sha256 `8a4f726272b0a1c499bd87ca3978bfbb1a8c20bb08ccf075b9996e2081bd1e1e` |
| cargo-deny | 0.20.2 | GitHub release binary, published sha256 checked |

## 4. Brand name

Availability checked on 2026-09-13 (npm package, crates.io, PyPI, GitHub user or org, domains via RDAP):

| Name | npm | crates.io | PyPI | GitHub | .dev | .com |
|---|---|---|---|---|---|---|
| **tesra** | free | free (no crates with the prefix) | free | taken by a dormant 2018 user with no repositories; `tesra-dev` is free | free | taken |
| tesfa | free | free | free | taken | taken | taken |
| tessary | free | free | free | taken | taken | not checked |
| tessera, tesserae, assay, plinth, cairn, sigil, keel, touchstone, bulwark, lintel, mosaiq | taken | mostly taken | taken | taken | taken or unknown | taken or unknown |
| ashlar, hallmark, watchword | taken | free | taken or free | taken | taken | taken |

**Why Tesra:** it's short and free on every registry that matters, and it comes from *tessera*. A tessera is a mosaic tile, like a component, and was also the tablet carrying a Roman watchword, like an auth token.

**Known name collisions:** unrelated small companies called TESRA operate in engineering simulation software (Egypt), industrial thermal products (Canada) and education technology (India). None is in developer tooling. This is not a trademark clearance; get one before significant commercial use.

## Sources

- [ASVS 5.0: What is the ASVS](https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x03-What-is-the-ASVS.md)
- [Google: OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [Microsoft: ID token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference) and [claims validation](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation)
- [GitHub changelog: PKCE support for OAuth and GitHub App authentication](https://github.blog/changelog/2025-07-14-pkce-support-for-oauth-and-github-app-authentication/)
- [OpenID Connect GitHub module (notes that GitHub doesn't implement OIDC for sign-in)](https://www.drupal.org/project/openid_connect_github)
- [Implementing Sign in with Apple (Scott Brady)](https://www.scottbrady.io/openid-connect/implementing-sign-in-with-apple-in-aspnet-core), [generating an Apple client secret per request](https://bannister.me/blog/generating-a-client-secret-for-sign-in-with-apple-on-each-request) and [Better Auth issue on expiring Apple secrets](https://github.com/better-auth/better-auth/issues/1522)
- [pnpm settings](https://pnpm.io/settings)
- [Dependabot minimum package age changelog](https://github.blog/changelog/2025-07-01-dependabot-supports-configuration-of-a-minimum-package-age/) and [Dependabot options reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference)
- [crates.io trusted publishing](https://crates.io/docs/trusted-publishing), [npm trusted publishing GA](https://github.blog/changelog/2025-07-31-npm-trusted-publishing-with-oidc-is-generally-available/) and [npm trusted publishers docs](https://docs.npmjs.com/trusted-publishers/)
- TESRA companies: [PitchBook](https://pitchbook.com/profiles/company/490738-15), [LinkedIn (Canada)](https://ca.linkedin.com/company/tesra-inc), [Tesra Edutech](https://www.tesragroup.com/about-us/)
- npm registry, crates.io, PyPI, GitHub REST and RDAP APIs
