# Audit request draft — TorDNS (English)

*This is a draft. Gary reviews it, fills in the dates and the current commit,
and submits it himself. Nobody is contacted by the project's agents.*

## Project

TorDNS is a free, open-source privacy DNS network for people in censored and
surveilled environments. A small client (Linux, macOS, Windows, Android,
OpenWrt) sends DNS queries through Tor to a hidden service whose relay answers
them; the client validates DNSSEC itself, so a malicious volunteer node cannot
silently forge an answer in signed zones. A public registry admits volunteer
nodes after automated soundness probes and evicts nodes that lie about DNSSEC
or addresses. Signed release manifests carry updates and the signed list of
service addresses.

- Repository: <https://github.com/garybourbier/tordns> (public, commit to be
  pinned at submission).
- Version: 0.8.0.
- Licence: free software (see `LICENSE`).
- Languages: Go (client relay, registry, tools), Rust (Windows client, Android
  Arti), Java (Android), Swift (iOS, in progress), shell and YAML (packaging,
  CI, node installer), JavaScript (LuCI page).

## Users and impact

Users are journalists, activists, and families in countries where the state or
the ISP inspects, blocks or forges DNS. Losing confidentiality means exposing
which sites a person visits; losing integrity means being redirected to a
look-alike site. TorDNS is designed so that no single volunteer, no registry
operator, and no hosting provider can read queries or forge signed answers.

The project is small and non-commercial. There is no funding for security
work, and the code is maintained by one person with automated tests but no
external review.

## What we ask for

An independent security audit of the components listed in
`docs/securite/perimetre-audit.md`, with priority on:

1. the DNS relay and its home-grown DNSSEC validation (memory safety, parser
   robustness against hostile packets, correctness of the validation paths);
2. the signed update manifest and the update/rollback logic on the node and
   the clients;
3. the volunteer registry: enrolment challenge, PROXY v2 trust, rate limits,
   probe soundness, admission and eviction;
4. the client leak-prevention logic on each platform.

Deliverable: a report with severity, exploitation scenario, suggested fix, and
a regression test we can add to `scripts/`. We will publish a summary and fix
findings; the threat model, the audit scope, and every known limitation are
already public in `docs/securite/`.

## Scope and logistics

- Everything runs locally: every security claim has a `scripts/verifier-mNN.sh`
  that rebuilds and tests it, without any production server (`docs/securite/perimetre-audit.md`).
- No production `.onion` address, no key, and no personal data are in the
  repository or needed for the audit; fixtures are generated on the fly.
- The audit can be done entirely on a Linux workstation with Docker; no access
  to Gary's infrastructure is required or offered.
- Estimated effort: 5–8 auditor-days for the priority components, 10–15 days
  for the full scope including mobile clients.

## Contact

Gary, maintainer — through the private GitHub security advisory form
(<https://github.com/garybourbier/tordns/security/advisories/new>) or the
address he provides in the application. Please do not open a public issue.
