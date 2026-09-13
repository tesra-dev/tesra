# Research baseline: September 2026

Collected 2026-09-13. Library versions, dates and download counts come from the crates.io, npm and GitHub APIs on that day. Standards come from their official publications. This is a snapshot, so redo it before each major release.

1. [Standards](#1-standards)
2. [Numbers that set our defaults](#2-numbers-that-set-our-defaults)
3. [Rust auth ecosystem](#3-rust-auth-ecosystem)
4. [Frontend ecosystem](#4-frontend-ecosystem)
5. [Passkeys in the browser](#5-passkeys-in-the-browser)
6. [Supply-chain check](#6-supply-chain-check)
7. [Sources](#7-sources)

## 1. Standards

| Standard | Version | Use in this project |
|---|---|---|
| OWASP ASVS | 5.0.0, released 2025-05-30 | The requirement spec. Every auth control maps to a requirement ID |
| NIST SP 800-63B | Revision 4, final (August 2025) | Password rules, attempt limits, session timeouts per assurance level |
| OWASP Cheat Sheet Series | Living documents | Implementation detail where ASVS is abstract |
| OWASP Top 10 | 2025, final | Risk framing: A07:2025 Authentication Failures, A03:2025 Software Supply Chain Failures |
| WCAG | 2.2, level AA | Accessibility bar for UI |
| WAI-ARIA Authoring Practices | Living document | Keyboard and ARIA behavior per widget |
| Design Tokens Format Module | 2025.10, first stable version (2025-10-28) | Token file format |

### ASVS 5.0 at a glance

ASVS 5.0 has 345 requirements in 17 chapters. A requirement's `L` value is the lowest level it applies to, so each level includes the ones below it. 70 requirements apply from L1, 183 more from L2 and 92 more from L3.

| Chapter | Total | L1 | L2 | L3 | Relevance to the auth kit |
|---|---|---|---|---|---|
| V2 Validation and Business Logic | 13 | 4 | 7 | 2 | V2.4 anti-automation |
| V3 Web Frontend Security | 31 | 8 | 11 | 12 | V3.3 cookies, V3.4 headers, V3.5 origin separation and CSRF |
| V6 Authentication | 47 | 13 | 22 | 12 | All of it |
| V7 Session Management | 19 | 6 | 12 | 1 | All of it |
| V8 Authorization | 13 | 4 | 3 | 6 | Possible later module |
| V9 Self-contained Tokens | 7 | 4 | 3 | 0 | Service tokens |
| V10 OAuth and OIDC | 36 | 5 | 24 | 7 | Client sections only (V10.1, V10.2, V10.5) |
| V11 Cryptography | 24 | 3 | 11 | 10 | V11.4 hashing, V11.5 randomness |
| V13 Configuration | 21 | 1 | 12 | 8 | V13.3 secret management (shared) |
| V14 Data Protection | 13 | 2 | 7 | 4 | V14.3 client-side data |
| V16 Security Logging and Error Handling | 17 | 0 | 16 | 1 | V16.3 security events |

The full list with a scope for each requirement is in [security/asvs-matrix.csv](../../security/asvs-matrix.csv).

## 2. Numbers that set our defaults

### Passwords

| Rule | Value | Source |
|---|---|---|
| Minimum length | 15 when the password is the only factor; 8 when used with MFA | NIST 800-63B-4 (SHALL). ASVS V6.2.1 requires 8 and strongly recommends 15 |
| Maximum length | Accept at least 64 characters | NIST (SHOULD), ASVS V6.2.9 |
| Composition rules | Forbidden | NIST (SHALL NOT), ASVS V6.2.5 |
| Periodic rotation | Forbidden. Force a change only on evidence of compromise | NIST (SHALL NOT), ASVS V6.2.10 |
| Blocklist | At least the top 3,000 passwords that meet the policy (L1), plus breached passwords (L2), plus context-specific words (L2) | ASVS V6.2.4, V6.2.12, V6.1.2 and V6.2.11 |
| Hints and security questions | Forbidden | NIST (SHALL NOT), ASVS V6.4.2 |
| Unicode | Accept, and normalize to NFC | NIST (SHOULD) |
| Comparison | Exactly as entered: no truncation, no case change | ASVS V6.2.8 |
| Paste and password managers | Must work | ASVS V6.2.7; OWASP Authentication CS |
| Failed attempts | No more than 100 consecutive failures before the authenticator is disabled | NIST (SHALL) |
| Storage | Argon2id m=19 MiB, t=2, p=1. Equivalent settings: 46 MiB/t=1, 12 MiB/t=3, 9 MiB/t=4, 7 MiB/t=5. Use scrypt (N=2^17, r=8, p=1) if Argon2id is unavailable. bcrypt (cost ≥10, 72-byte limit) is for legacy systems only. Use PBKDF2-HMAC-SHA256 with 600,000 iterations where FIPS-140 is required | OWASP Password Storage CS; ASVS V11.4.2 |
| Legacy hashes | Rehash with the current algorithm on the next successful sign-in | OWASP Password Storage CS |

### Sessions and cookies

| Rule | Value | Source |
|---|---|---|
| Session token entropy | At least 128 bits from a CSPRNG | ASVS V7.2.3. The OWASP cheat sheet says 64; we follow ASVS |
| Any value that must be unguessable | At least 128 bits from a CSPRNG; UUIDs don't qualify | ASVS V11.5.1 |
| New token on sign-in or re-authentication | Always, and end the old session | ASVS V7.2.4 |
| Cookie attributes | `__Host-` prefix, `Secure`, `HttpOnly` on session tokens, `SameSite` chosen per cookie | ASVS V3.3.1–V3.3.4; OWASP Session Management CS |
| Where tokens may live | Never in localStorage or sessionStorage | OWASP Session Management CS; ASVS V14.3.3 |
| AAL1 timeouts | Absolute ≤30 days; idle timeout optional | NIST 800-63B-4 (SHOULD) |
| AAL2 timeouts | Absolute ≤24 hours; idle ≤1 hour | NIST (SHOULD) |
| AAL3 timeouts | Absolute ≤12 hours (SHALL); idle ≤15 minutes (SHOULD) | NIST |
| Re-authentication | Before changing email, phone, MFA or recovery details | ASVS V7.5.1 |
| Session control | Users can view and end their sessions; admins can end any user's sessions; disabling an account ends all its sessions | ASVS V7.5.2, V7.4.5, V7.4.2 |
| Sign-out | Invalidate on the server, send `Clear-Site-Data`, set `Cache-Control: no-store` | ASVS V7.4.1, V14.3.1, V14.3.2 |

### MFA and recovery

| Rule | Value | Source |
|---|---|---|
| Out-of-band codes and links | Expire within 10 minutes; bound to the originating request; rate limited | ASVS V6.5.5, V6.6.2, V6.6.3 |
| TOTP | Maximum lifetime 30 seconds; single use; server time only | ASVS V6.5.5, V6.5.1, V6.5.8 |
| Lookup secrets (recovery codes) | At least 20 bits of entropy. Stored secrets under 112 bits must use a password hashing function with a 32-bit salt; at 112 bits or more a standard hash is allowed | ASVS V6.5.4, V6.5.2 |
| WebAuthn challenge | At least 64 bits | ASVS V6.7.2 |
| SMS or voice OTP | A "restricted" authenticator: only with a validated number and a stronger alternative on offer. Forbidden at L3 | NIST 800-63B-4; ASVS V6.6.1 |
| Email as a factor | Forbidden at L3 | ASVS V6.3.6 |
| Phishing-resistant authenticators | WebAuthn/passkeys and client-authenticated TLS. Passwords, OTPs, lookup secrets and out-of-band codes don't qualify | NIST 800-63B-4 |
| Password reset | CSPRNG token, stored hashed, single use, expiring. Same response for existing and unknown accounts. Per-account rate limit. `Referrer-Policy: no-referrer`. Never build links from the Host header. No automatic sign-in. Offer to end other sessions. Confirm by email | OWASP Forgot Password CS; ASVS V7.4.3 |
| Reset versus MFA | A reset must not bypass MFA | ASVS V6.4.3 |
| MFA bypass flaws to test | Push fatigue, real-time phishing proxies, SIM swap, device-binding bypass, downgrade through legacy endpoints, reusable recovery codes, OTPs in logs | OWASP MFA CS |

### Enumeration and brute force

| Rule | Value | Source |
|---|---|---|
| Account enumeration | Same message, status code and timing for every failure, including in sign-up and password reset | ASVS V6.3.8; OWASP Authentication CS |
| Throttling | Count failures per account, not only per IP. Use exponential backoff. Avoid lockouts attackers can abuse, and document the controls | OWASP Authentication CS; ASVS V6.1.1, V6.3.1 |
| Credential stuffing | MFA first. Then CAPTCHA on suspicious requests, IP reputation, device and TLS fingerprinting, breached-password checks and notifying users | OWASP Credential Stuffing CS |

### CSRF for cookie sessions with a JSON API

- **Primary defense is a token.** OWASP marks the signed double-submit cookie (an HMAC bound to the session) as recommended; synchronizer tokens also work.
- **Custom request headers** suit fetch-based apps because they force a CORS preflight.
- **Fetch Metadata** (`Sec-Fetch-Site`) is acceptable when only modern browsers are supported, with fallbacks.
- **SameSite and Origin/Referer checks** are defense in depth only. Legitimate requests omit Origin roughly 1–2% of the time.
- **ASVS V3.5.1–V3.5.3** accept anti-forgery tokens, non-safelisted headers or strict `Sec-Fetch-*` validation.

### Browser headers

| Header | Requirement | ASVS |
|---|---|---|
| HSTS | `max-age` of at least 1 year; `includeSubDomains` from L2 | V3.4.1 |
| CSP | At least `object-src 'none'` and `base-uri 'none'` with an allowlist, nonces or hashes (L2); per-response nonces or hashes (L3); `frame-ancestors` against framing | V3.4.3, V3.4.6 |
| `X-Content-Type-Options`, `Referrer-Policy` | Required from L2 | V3.4.4, V3.4.5 |
| COOP | `same-origin` or `same-origin-allow-popups` on documents (L3) | V3.4.8 |
| CORS | Fixed origin or validated allowlist | V3.4.2 |

## 3. Rust auth ecosystem

Local toolchain: rustc and cargo 1.96.0. "Updated" is crates.io's `updated_at`; downloads cover the last 90 days.

| Crate | Version | Updated | 90-day downloads | Role | Verdict |
|---|---|---|---|---|---|
| axum | 0.8.9 | 2026-04-14 | 115.0M | HTTP framework | Adopt |
| tower-http | 0.7.1 | 2026-08-31 | 144.4M | CORS, headers, tracing layers | Adopt |
| argon2 (RustCrypto) | 0.6.0 | 2026-08-27 | 18.9M | Argon2id, PHC strings, optional zeroize | Adopt |
| password-hash | 0.6.1 | 2026-04-08 | 32.1M | PHC string handling | Adopt, via argon2 |
| webauthn-rs | 0.5.5 | 2026-04-30 | 2.5M | Passkeys and security keys. Passed a SUSE security audit. Maintainers recommend the safe API. Conditional UI sits behind the `conditional-ui` feature | Adopt |
| totp-rs | 6.0.0 | 2026-08-06 | 3.0M | TOTP | Adopt |
| openidconnect | 4.0.1 | 2025-07-06 | 3.9M | OIDC relying party | Adopt; releases are slow, so watch |
| oauth2 | 5.0.0 | 2025-01-21 | 12.4M | OAuth 2 client, used by openidconnect | Adopt; releases are slow, so watch |
| jsonwebtoken | 11.0.0 | 2026-07-24 | 47.5M | Service-to-service JWTs | Adopt, with an algorithm allowlist |
| pasetors | 0.8.1 | 2026-08-30 | 1.5M | PASETO v4 | Evaluate as a JWT alternative |
| governor | 0.10.4 | 2025-12-16 | 15.1M | GCRA rate limiting | Adopt |
| tower_governor | 0.8.0 | 2025-08-14 | 1.7M | Tower layer for governor | Evaluate; per-account keys probably need our own layer |
| tower-sessions | 0.15.0 | 2026-02-01 | 0.85M | Generic sessions | Skip: we need tokens hashed at rest plus ASVS-specific rotation and timeouts |
| axum-login | 0.18.0 | 2025-07-20 | 0.19M | Auth middleware | Skip: duplicates our layer, and no release in 14 months |
| sqlx | 0.9.0 | 2026-05-21 | 36.4M | Postgres | Adopt |
| rand | 0.10.2 | 2026-08-25 | 427.7M | CSPRNG | Adopt |
| subtle | 2.6.1 | 2024-06-24 | 158.9M | Constant-time comparison | Adopt; stable and complete |
| hmac, sha2 | 0.13.0, 0.11.0 | 2026-03 | 146.3M, 249.4M | HMAC-SHA256, SHA-256 | Adopt |
| zeroize, secrecy | 1.9.0, 0.10.3 | 2026-06-12, 2024-10-09 | 173.6M, 39.1M | Wipe and wrap secrets in memory | Adopt |
| zxcvbn | 3.1.1 | 2026-04-24 | 1.5M | Server-side strength estimate | Evaluate |
| lettre | 0.11.23 | 2026-08-03 | 5.9M | Email | Adopt |
| cookie | 0.18.2 | 2026-08-08 | 50.8M | Cookie building and parsing | Adopt |
| utoipa | 5.5.0 | 2026-05-04 | 14.3M | OpenAPI from Rust types | Adopt |
| redis | 1.7.0 | 2026-09-05 | 25.3M | Shared rate-limit store | Later |

**Pwned Passwords range API.** Checked live on 2026-09-13: it returned HTTP 200 with no API key, and `Add-Padding` works. Only the first 5 hex characters of the password's SHA-1 hash leave the server.

### Rust quality tooling

| Tool | Version | Purpose |
|---|---|---|
| cargo-nextest | 0.9.144 | Test runner |
| cargo-llvm-cov | 0.9.1 | Coverage |
| proptest | 1.11.0 | Property tests |
| insta | 1.48.0 | Snapshot tests |
| testcontainers | 0.28.0 | Real Postgres in tests |
| cargo-fuzz | 0.13.2 | Fuzzing |
| cargo-mutants | 27.1.0 | Mutation testing |
| cargo-deny, cargo-audit | 0.20.2, 0.22.2 | Advisories, licenses, banned crates |
| release-plz | 0.3.165 | Crate releases |

## 4. Frontend ecosystem

npm `latest` tags on 2026-09-13; downloads cover the last week.

### Core

| Package | Version | Weekly downloads | Notes |
|---|---|---|---|
| react, react-dom | 19.3.0 | 128.1M | |
| typescript | 7.0.2 | 203.4M | Native compiler. typescript-eslint doesn't support it yet ([details](2026-09-providers-and-tooling.md#typescript-7)) |
| tailwindcss | 4.3.3 | 92.7M | v4.3 released 2026-05-08; CSS-first configuration |
| vite | 8.3.0 | 132.5M | |
| next | 16.3.5 | 43.4M | |
| shadcn (CLI) | 4.21.0 | 7.3M | Registry features below |
| cn | 0.3.0 | 1.6M | shadcn's `cn` helper as a standalone package (September 2026) |

### Headless primitives

| Library | Package | Version | Weekly downloads | Status |
|---|---|---|---|---|
| Base UI | @base-ui/react | 1.8.0 | 9.7M | Stable v1 (reported December 2025), maintained full-time by MUI. shadcn's default for new projects since July 2026. The old `@base-ui-components/react` package is deprecated after the rename |
| Radix Primitives | radix-ui | 1.6.7 | 10.1M | Not deprecated, but releases have slowed. shadcn still supports it |
| React Aria Components | react-aria-components | 1.21.1 | 3.1M | From Adobe. The most rigorous accessibility and i18n. shadcn added React Aria variants in July 2026 |

### shadcn registry (how the UI kit ships)

- **Item types:** UI components, blocks, hooks, libraries, themes and styles, described by `registry.json` and `registry-item.json` and built with the CLI.
- **Namespaces:** consumers install with `shadcn add @brand/component` and can combine several registries.
- **Private registries:** authentication is supported, and since August 2026 private GitHub repositories work too.
- **Tooling:** server-side search for large registries (July 2026) and an MCP server (August 2025).

### Testing and quality

| Package | Version | Weekly downloads | Notes |
|---|---|---|---|
| storybook | 10.6.0 | 16.0M | With @storybook/addon-vitest (turns stories into browser tests) and @storybook/addon-a11y (axe) |
| vitest | 5.0.0 | 77.1M | Browser mode via @vitest/browser-playwright 5.0.0 |
| @playwright/test | 1.63.0 | 45.8M | E2E and screenshots |
| axe-core | 4.13.0 | 51.5M | Accessibility rules engine |
| @testing-library/react | 16.3.3 | 43.0M | |
| @biomejs/biome | 2.5.13 | 11.0M | Linter and formatter |
| knip | 6.35.1 | 10.7M | Unused files, exports and dependencies |
| publint, @arethetypeswrong/cli | 0.3.24, 0.18.5 | 0.9M, 0.5M | Package correctness |
| size-limit | 13.1.1 | 0.9M | Bundle budgets |
| turbo | 2.10.12 | 18.0M | Monorepo task runner |
| @changesets/cli | 3.0.2 | 3.4M | npm versioning |

For visual regression, note that the Storybook Vitest addon doesn't support Vitest's `toMatchScreenshot`. Typical setups use Chromatic (hosted, paid) or Playwright screenshots.

### App building blocks

| Package | Version | Weekly downloads |
|---|---|---|
| react-hook-form | 7.88.0 | 40.0M |
| zod | 4.6.4 | 209.2M |
| @tanstack/react-form | 1.33.5 | 2.2M |
| input-otp | 1.5.0 | 22.3M |
| motion | 13.2.0 | 15.4M |
| sonner | 2.0.8 | 34.9M |
| lucide-react | 1.45.0 | 74.1M |
| @zxcvbn-ts/core | 4.2.0 | 1.1M |
| @tanstack/react-query | 5.102.8 | 45.6M |
| @hey-api/openapi-ts | 0.99.0 | 3.4M |
| orval | 8.32.0 | 1.6M |

### Design tokens

DTCG Format Module 2025.10 is the first stable version, released 2025-10-28. More than 40 organizations back it, including Adobe, Figma, Google, Microsoft, Shopify and Salesforce. It covers theming, multiple brands, modern color spaces (Display P3, OKLCH) and aliases. Build tools: style-dictionary 5.5.3 and @terrazzo/cli 2.7.1.

### Watch list

These common shadcn dependencies haven't released in a long time. Pin them, and be ready to vendor or replace them.

| Package | Version | Last modified | Used for |
|---|---|---|---|
| vaul | 1.1.2 | 2024-12-14 | Drawer |
| class-variance-authority | 0.7.1 | 2024-11-26 | Variants |
| next-themes | 0.4.6 | 2025-03-11 | Theme switching |
| cmdk | 1.1.1 | 2025-08-27 | Command menu |
| clsx | 2.1.1 | 2025-06-27 | Class joining; probably just finished |

### Component collections to study

shadcn/ui is the baseline. Origin UI has advanced primitives, Kibo UI has higher-level business components, Magic UI and Aceternity UI focus on animation and marketing, and Tailark builds marketing pages. Study their patterns rather than importing them wholesale. Check each license: several have paid Pro tiers whose code can't be redistributed.

## 5. Passkeys in the browser

- **JSON helpers:** `PublicKeyCredential.parseCreationOptionsFromJSON`, `parseRequestOptionsFromJSON` and `toJSON` have been Baseline since 2025-03-31 (Chrome and Edge 129, Firefox 119, Safari 18.4). A wrapper such as @simplewebauthn/browser 14.0.0 is optional.
- **Conditional create** (a passkey created automatically after a password sign-in) works in Safari on macOS, every browser on iOS, and Chrome on desktop and Android.
- **Feature detection:** use `PublicKeyCredential.getClientCapabilities()`, e.g. `conditionalGet` and `passkeyPlatformAuthenticator`.
- **Registration options:** `excludeCredentials` prevents duplicate registrations. `pubKeyCredParams` lists ES256 (-7) and RS256 (-257). A resident key enables sign-in without a username. Set `userVerification: "preferred"`.
- **What to store** per credential: ID, public key, AAGUID (for provider names such as "iCloud Keychain"), backup eligibility, and created and last-used dates. Email the user when a passkey is added.
- **Signal API:** call `signalUnknownCredential` when the server rejects an unknown credential, so the passkey provider can remove it.

## 6. Supply-chain check

Checked against the RustSec advisory database on 2026-09-13. The versions in section 3 contain every fix.

| Crate | Advisory | Fixed in |
|---|---|---|
| rand | RUSTSEC-2026-0097 (unsound) | ≥0.10.1 (also 0.9.3 and 0.8.6) |
| time | RUSTSEC-2026-0009 | ≥0.3.47 |
| lettre | RUSTSEC-2026-0141 | ≥0.11.22 |
| sqlx | RUSTSEC-2024-0363 | ≥0.8.1 |
| totp-rs | RUSTSEC-2022-0018 | ≥1.1.0 |
| sha2, tower-http, cookie, hyper | Older advisories (2016–2022) | Fixed long ago |

No advisories: axum, argon2, password-hash, webauthn-rs, oauth2, openidconnect, jsonwebtoken, pasetors, governor, tower-sessions, secrecy, zeroize, subtle, hmac, zxcvbn, reqwest, uuid, base64ct, redis. The tokio lookup failed; cargo-audit in CI covers it.

## 7. Sources

Standards
- [OWASP ASVS project](https://owasp.github.io/www-project-application-security-verification-standard) and [ASVS releases](https://github.com/OWASP/ASVS/releases)
- [NIST SP 800-63B Rev. 4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- OWASP cheat sheets: [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [Multifactor Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html), [Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html), [Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [OWASP Top 10:2025 A07 Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/) and [Fastly's summary of the 2025 list](https://www.fastly.com/blog/new-2025-owasp-top-10-list-what-changed-what-you-need-to-know)
- [DTCG first stable specification announcement](https://www.w3.org/community/design-tokens/2025/10/28/design-tokens-specification-reaches-first-stable-version/)

Rust
- [webauthn-rs repository](https://github.com/kanidm/webauthn-rs) and [docs](https://docs.rs/webauthn-rs/latest/webauthn_rs/)
- [argon2 crate docs](https://docs.rs/argon2/latest/argon2/)
- [axum releases](https://github.com/tokio-rs/axum/releases)
- [axum-login](https://github.com/maxcountryman/axum-login)
- [RustSec advisory database](https://github.com/rustsec/advisory-db)
- [Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- crates.io API (`/api/v1/crates/<name>`)

Frontend
- [shadcn/ui changelog](https://ui.shadcn.com/docs/changelog) and [registry docs](https://ui.shadcn.com/docs/registry)
- [Top headless UI libraries for React in 2026 (GreatFrontEnd)](https://www.greatfrontend.com/blog/top-headless-ui-libraries-for-react-in-2026) and [Radix vs Base UI (ShadcnDeck)](https://www.shadcndeck.com/blog/radix-vs-base-ui)
- Storybook docs: [Vitest addon](https://storybook.js.org/docs/writing-tests/integrations/vitest-addon), [accessibility tests](https://storybook.js.org/docs/writing-tests/accessibility-testing), [discussion on `toMatchScreenshot`](https://github.com/storybookjs/storybook/discussions/32930)
- [Tailwind CSS blog](https://tailwindcss.com/blog)
- [shadcn UI libraries overview (WrapPixel)](https://wrappixel.com/blog/shadcn-ui-libraries)
- npm registry and downloads APIs

Passkeys
- [web.dev: passkey registration](https://web.dev/articles/passkey-registration)
- [Chrome: conditional create](https://developer.chrome.com/docs/identity/webauthn-conditional-create)
- [Chrome 129: hints, Related Origin Requests, JSON serialization](https://developer.chrome.com/blog/passkeys-updates-chrome-129)
