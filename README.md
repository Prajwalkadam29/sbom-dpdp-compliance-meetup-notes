# DPDP, RBI & the BOM Family: A DevOps/SRE Study Guide

Product-neutral notes based on a live webinar on SBOM and DPDP compliance for Indian banks.
Audience: DevOps/SRE engineers who are new to compliance.
Not legal advice. Verify clauses with your compliance/legal team.

---

## 1. The one-minute version

Regulators (DPDP, RBI, CERT-In) all ask the same thing:

> Prove, with evidence, that you know what you run, where personal data lives,
> and which controls protect it.

The answer is one repeating loop:

```
Inventory -> Assess gaps -> Prioritise -> Remediate -> Produce dated evidence -> Repeat
```

The law does **not** punish you for being breached. It punishes you for being unable to show
you took *reasonable* safeguards. Evidence is your defence.

---

## 2. Regulatory cheat sheet

### DPDP Act 2023 and DPDP Rules 2025
| Term | Meaning |
|---|---|
| Data Principal | The person the data is about (bank customer) |
| Data Fiduciary | The organisation deciding how data is used (the bank). Responsible even when vendors hold the data |
| Personal data | Anything identifying a person: name, phone, Aadhaar, PAN, account no., device IDs |

| Date | Event |
|---|---|
| 14 Nov 2025 | Rules notified, Data Protection Board constituted |
| Nov 2026 | Consent Manager registration framework starts |
| Mar 2027 | **Recommended internal readiness target. Not a legal date.** Aligns with financial-year-end audits |
| 13 May 2027 | Full obligations enforceable (notice, safeguards, breach duties) |

**Rule 6 safeguards (engineering view):**
- Encryption / masking / obfuscation / tokens
- Access control
- Logging and monitoring for unauthorised access
- Backups and continuity
- Logs retained at least **1 year**
- Processor (vendor) contracts that require the same safeguards

**Breach duties:** inform affected people without delay; inform the Board without delay and
send a detailed report within **72 hours**.

**Maximum penalties (not automatic):** up to INR 250 Cr (failing reasonable safeguards),
up to INR 200 Cr (failing to notify a breach).

### Other regulators
| Source | What it cares about |
|---|---|
| RBI Cyber Security Framework (2016) | Board-approved cyber policy, continuous surveillance, detect/contain/respond |
| RBI Master Direction on IT Governance, Risk, Controls and Assurance (eff. 1 Apr 2024) | IT governance, asset inventory, patch management, audit trails |
| CERT-In | Incident reporting within 6 hours, log retention 180 days, BOM guidelines v2.0 |

Overlap is the point: build one control and one evidence stream, then map to many frameworks.

---

## 3. Asset inventory (the foundation)

You cannot protect, patch, or prove what you do not know exists.

| Layer | Examples |
|---|---|
| Cloud | Accounts, buckets, IAM, databases, load balancers |
| Infrastructure | VMs, Kubernetes clusters/nodes/pods, bare metal |
| Applications | Repos, container images, libraries, APIs, secrets |
| Network | Subnets, open ports, egress paths |
| Data | Databases, backups, logs, exports, analytics stores |

**Hard parts:** ephemeral assets (pods live minutes), shadow assets (forgotten test DBs),
fragmented tools (each sees one slice).

**Where personal data hides:** application logs, backups/snapshots, object-storage exports,
dev/test copies of prod, analytics pipelines, queues/caches, third-party API calls.

**Do this:**
1. Pull inventory from authoritative APIs (cloud, Kubernetes, Git, CMDB), continuously.
2. Tag assets: owner, environment, criticality, data-classification.
3. Run data discovery for PAN/Aadhaar/phone/email patterns.
4. Reconcile cloud vs CMDB; unknown assets are findings.

---

## 4. SBOM: Software Bill of Materials

An ingredient list for software: every component inside it, machine-readable.

**Why:** supply-chain attacks and surprise CVEs (Log4Shell 2021, SolarWinds 2020, xz 2024).
It answers: "Vulnerability X was announced. Which of my services are affected?"

**Minimum contents per component:** name, version, supplier, unique ID (purl/CPE), hashes,
license, dependency relationships, SBOM author, timestamp.

Example purl: `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`

| Format | Owner | Notes |
|---|---|---|
| CycloneDX | OWASP / Ecma | Security-focused; supports VEX, CBOM, ML-BOM |
| SPDX | Linux Foundation (ISO) | License-compliance roots |

### Build-time vs runtime generation
| | Build time (CI) | Runtime (image/registry/cluster scan) |
|---|---|---|
| Strength | Accurate dependency tree tied to the release | Shows what is actually deployed, incl. OS packages |
| Weakness | Misses post-build changes | Less precise on dependency relationships |

Best practice: **do both**, then compare (drift).

### Example pipeline
```bash
# Generate an SBOM from a container image
syft scan myapp:1.4.2 -o cyclonedx-json > sbom.cdx.json

# Scan it for known vulnerabilities; fail the build on high severity
grype sbom:sbom.cdx.json --fail-on high

# Sign and attach to the image
cosign attest --predicate sbom.cdx.json --type cyclonedx myregistry/myapp:1.4.2
```
Other tools: Trivy, cdxgen, Dependency-Track (continuous re-scanning platform).

### Key ideas
- **An SBOM is static; vulnerabilities are not.** Re-match stored SBOMs against fresh feeds
  (NVD, OSV, GitHub Advisories, CISA KEV) continuously.
- **Triage by:** exploited in the wild (KEV/EPSS), reachable, internet-facing or holds PII, fix available.
- **VEX** states whether you are actually affected: `not_affected`, `affected`, `fixed`,
  `under_investigation`. Cuts false-positive noise.
- **SBOM diff:** compare release N vs N-1 (added/removed/upgraded components). Useful for
  review and incident forensics.
- **SRE caution:** start gates in warn-only mode; cache vulnerability DBs so an outage does
  not block deploys; version and retain SBOMs per release.

---

## 5. CBOM and QBOM: cryptography

**CBOM** = inventory of all cryptography: algorithms, key sizes, certificates, protocols,
cipher suites, libraries (OpenSSL, BouncyCastle, Go crypto).

Uses:
- Find weak crypto (MD5, SHA-1, DES, RSA-1024, TLS 1.0/1.1, hardcoded keys)
- Evidence for DPDP encryption safeguards
- Quantum migration planning
- **Prevent certificate-expiry outages**

```bash
# Check a certificate's expiry
echo | openssl s_client -connect api.bank.example:443 2>/dev/null | openssl x509 -noout -enddate
```
Monitor continuously: Prometheus `blackbox_exporter` metric
`probe_ssl_earliest_cert_expiry`; alert at 30/14/7 days. Automate renewal (cert-manager, ACME).
Public cert lifetimes are shrinking (heading toward 47 days by 2029), so manual renewal will not scale.

**Crypto-agility:** design so algorithms can be swapped by config, not code rewrite.

**QBOM / quantum risk**
- A large quantum computer could break public-key crypto (RSA, ECC, DH). AES-256 and hashes are far less affected.
- Webinar correction: breaking RSA-2048 is estimated to need about a million noisy physical
  qubits, not "900". Not imminent.
- Real threat: **harvest now, decrypt later**. Attackers record traffic today, decrypt later.
  Long-lived sensitive data (KYC, loan files) is most exposed.
- QBOM = the quantum-vulnerable subset of your CBOM, i.e. a migration to-do list.
- NIST PQC standards: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205).
- Path: inventory -> prioritise long-lived data -> pilot hybrid TLS -> migrate gradually.

---

## 6. AIBOM, HBOM, xBOM

| BOM | Inventories | Why |
|---|---|---|
| AIBOM | ML models: version, source, training-data lineage, license, approver | Unvetted/poisoned models are a supply-chain risk; fraud/credit models in banks |
| HBOM | Hardware and firmware: servers, HSMs, network gear | Firmware CVEs; matters for on-prem |
| xBOM | All of the above managed together | One view of the supply chain |

---

## 7. Data protection controls

| Control | What it does | Reversible? | SRE concern |
|---|---|---|---|
| Encryption | Scramble data with a key | Yes, with key | Key rotation, KMS outage, never lose keys |
| Masking | Hide part of data (`XXXXXX1234`) | No / view-level | Needed for dev/test copies |
| Tokenization | Replace with random token; real value in a vault | Only via vault | Vault is a critical dependency: HA, latency, fail-closed behaviour |
| Consent mgmt | Track permission and purpose; honour withdrawal | n/a | Propagate withdrawals to all downstream systems |

**Encryption details**
- At rest (disks, DBs, object storage); in transit (TLS, mTLS in-cluster)
- Envelope encryption: data encrypted by a DEK; DEK encrypted by a KEK held in KMS/HSM
  (rotate KEK cheaply by re-wrapping)
- KMS = managed key service; HSM = tamper-resistant hardware, keys never leave

**Masking:** static (sanitised copies for non-prod) vs dynamic (per-user views).

**Tokenization vs encryption:** tokens have no mathematical link to the original; shrinks the
number of systems holding real data.

**Consent:** purpose limitation. Implement `consent.withdrawn` events; consumers act idempotently.

### Who does what
| Requirement | Scanners can verify | Actually done by |
|---|---|---|
| Encryption | Config checks, CBOM | KMS/HSM, TLS, storage encryption |
| Masking | Find unmasked data | DB masking / DLP |
| Tokenization | Vault access paths | Token vault |
| Consent | Not covered | Consent Manager / CMP |

A visibility tool proves a control exists. It is not the control.

---

## 8. Compliance as code and evidence

- **Control** = one testable rule. **Framework** = bundle of controls (DPDP, RBI MD-ITF, CIS, PCI DSS).
- **Score** = % controls passing. Always ask how it is computed (weighting, exclusions).
- One finding can map to several frameworks. Map once, reuse.

| Layer | Tools |
|---|---|
| IaC scanning | Checkov, tfsec, Trivy |
| Kubernetes policy | OPA Gatekeeper, Kyverno |
| Cloud posture | Prowler, Cloud Custodian |
| K8s/node benchmarks | kube-bench |
| Runtime detection | Falco, KubeArmor, Tetragon |
| Secrets | gitleaks, trufflehog |

### What auditors want
1. Inventory of systems and the personal data they process
2. Proof of safeguards (access control, encryption, config, monitoring)
3. Detection, investigation and response records
4. A repeatable gap-finding and remediation process

Make evidence a **byproduct** of the pipeline (dated scan reports, signed SBOMs, change tickets,
policy-pass logs, access reviews). Manual screenshots before an audit = toil.

### Logging
- Keep personal-data processing logs >= 1 year (DPDP); use the longest applicable period.
- Tamper-evident, centralised, write-once storage (e.g. object lock).
- Never log raw personal data; mask first.
- Tier storage (hot ~30 days, cold afterwards).

### Breach runbook (72-hour clock)
1. Detect
2. Triage, declare incident, start clock, name incident commander
3. Contain (revoke credentials, isolate workloads)
4. Assess: what data, how many people, which systems
5. Notify: individuals, Board (detailed report within 72h), CERT-In (6h), RBI per its rules
6. Recover, post-mortem, retain evidence

Rehearse with game days.

---

## 9. Five-month roadmap

| Month | Phase | Actions |
|---|---|---|
| Nov | Discover | Connect cloud, clusters, repos; build asset and data inventory |
| Dec | Assess | Run DPDP and RBI control checks; baseline the score |
| Jan | Inventory | Generate SBOM and CBOM for critical apps; flag quantum-vulnerable crypto |
| Feb | Remediate | Fix highest-risk gaps; enforce admission and runtime policies |
| Mar | Prove | Export dated evidence per framework; run a breach drill |

Limited time? Start with business-critical, customer-data-facing apps and finish those end to end.

---

## 10. SRE checklist

**Inventory**
- [ ] Continuous discovery of cloud, Kubernetes, repos (covers ephemeral assets)
- [ ] Every asset tagged: owner, env, criticality, data classification
- [ ] Data stores scanned for PII, including logs, backups, non-prod

**Supply chain**
- [ ] SBOM generated in CI for every release (CycloneDX or SPDX)
- [ ] SBOMs signed and stored per release
- [ ] Continuous re-scan against fresh vulnerability feeds
- [ ] VEX used to suppress not-affected findings
- [ ] Runtime vs build SBOM drift checked

**Crypto**
- [ ] CBOM covers TLS, certs, keys, libraries
- [ ] Certificate-expiry alerts and automated renewal
- [ ] Weak algorithms and protocols tracked to closure
- [ ] Quantum-vulnerable, long-lived data identified

**Data controls**
- [ ] Encryption at rest and in transit verified
- [ ] KMS/HSM key rotation and audit logging working
- [ ] Non-prod uses masked data
- [ ] Token vault HA tested; failure behaviour defined
- [ ] Consent-withdrawal events reach all downstream systems

**Evidence and response**
- [ ] Controls scanned continuously; dated reports retained
- [ ] Logs retained >= 1 year, tamper-evident, no raw PII
- [ ] Breach runbook written and drilled (72h Board report, 6h CERT-In)

---

## 11. Good questions to ask any vendor

1. Agent-based or agentless discovery? What is the production overhead?
2. How are ephemeral pods/VMs captured?
3. Where are SBOMs generated (CI vs runtime), and which formats are supported?
4. How fast can I find every service affected by a new CVE?
5. Does it fail open or fail closed if the tool itself breaks?
6. HA/DR story, upgrade path, air-gapped support?
7. What telemetry does the tool expose (metrics, logs, traces)?
8. How is the compliance score computed?

---

## 12. Glossary

| Term | Plain meaning |
|---|---|
| SBOM | Ingredient list of software |
| CBOM | Inventory of cryptography in use |
| QBOM | Quantum-vulnerable crypto list |
| AIBOM | Inventory of AI models and their origins |
| HBOM | Inventory of hardware and firmware |
| xBOM | All BOMs together |
| CycloneDX / SPDX | The two standard SBOM formats |
| purl / CPE | Unique component identifiers |
| CVE | Public ID for a known vulnerability |
| KEV / EPSS | Exploited-in-the-wild list / exploit-likelihood score |
| VEX | Statement of whether a CVE actually affects you |
| KMS / HSM | Key management service / hardware key vault |
| DEK / KEK | Data key / key that wraps data keys |
| PQC | Post-quantum cryptography |
| Crypto-agility | Ability to swap algorithms easily |
| Data Fiduciary | Organisation responsible for personal data (the bank) |
| Data Principal | The person the data belongs to |
| Consent Manager | Registered entity for managing user consent |
| Control / Framework | One testable rule / bundle of rules |
| Drift | Difference between what you declared and what is running |
| Toil | Repetitive manual work that automation should replace |

---
