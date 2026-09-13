# Tesra

Tesra is a framework for building products that are secure and accessible from the first commit.

- **Auth kit.** Rust authentication (axum) with a TypeScript client, React hooks and UI blocks, held to OWASP ASVS 5.0 Level 2 by default. Every security control is proven by a named test, and CI rejects any claim that no passing test backs.
- **UI kit.** React components on Base UI primitives, held to WCAG 2.2 AA and distributed as a shadcn registry you copy into your project.

The name comes from *tessera*: a tile in a mosaic, and the tablet Roman soldiers carried the watchword on.

> **Status:** Phase 0 (foundation), September 2026. Nothing is published yet.

## Repository

| Path | Contents |
|---|---|
| [crates/](crates/) | Rust auth crates: `tesra-auth-core`, `tesra-auth-axum`, `tesra-auth-postgres`, `tesra-auth-testkit` |
| [security/asvs-matrix.csv](security/asvs-matrix.csv) | All 345 ASVS 5.0 requirements with scope, status, implementation and tests |
| [scripts/asvs_gate.py](scripts/asvs_gate.py) | Gate that holds the matrix to ASVS and to CI test results |
| [docs/blueprint.md](docs/blueprint.md) | Architecture, decisions, assurance profiles, testing strategy, roadmap |
| [docs/research/](docs/research/) | Evidence behind every decision, with sources |
| [standards/owasp-asvs-5.0.0/](standards/owasp-asvs-5.0.0/) | Upstream ASVS data ([license notice](standards/owasp-asvs-5.0.0/NOTICE.md)) |

## Standards

OWASP ASVS 5.0.0 · NIST SP 800-63B Rev. 4 · OWASP Cheat Sheet Series · OWASP Top 10:2025 · WCAG 2.2 AA · WAI-ARIA Authoring Practices · DTCG Design Tokens 2025.10

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Code is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. The ASVS data in `standards/` and the requirement text in `security/asvs-matrix.csv` are licensed CC BY-SA 4.0 ([notice](standards/owasp-asvs-5.0.0/NOTICE.md)).
