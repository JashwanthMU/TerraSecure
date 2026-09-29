# TerraSecure v2.1.0 - Multi-Cloud Support: AWS, Azure, GCP

TerraSecure now scans **AWS, Azure, and GCP** Terraform resources in a single run - including mixed-provider configurations, where an `aws_s3_bucket` and an `azurerm_storage_account` sit in the same file or directory. Each resource is routed to the correct cloud's rule engine independently and tagged with its provider in every output format.

## Highlights

- **122 security patterns** across three clouds: AWS (50), Azure (50), GCP (22, v1)
- **Per-resource provider routing** - mixed-cloud Terraform configs are scanned correctly, not just single-cloud repos
- **`--cloud` filter** - `--cloud aws`, `--cloud azure,gcp`, or omit for all detected clouds
- **Cloud-tagged output** everywhere: text (`[AWS]`/`[AZURE]`/`[GCP]` per finding + a by-cloud summary), JSON (`cloud_breakdown`), and SARIF (`cloud` + `security-severity` properties per result, so GitHub's Security tab can filter and color by both)
- **New `action.yml`** - TerraSecure is now consumable as a proper GitHub Marketplace composite action, with `path`/`format`/`fail-on`/`cloud`/`output` inputs and `issues-found`/`critical-count`/`cloud-breakdown`/`sarif-file` outputs
- **75 new unit tests** (37 for the Azure rule engine, 38 for GCP) plus CI regression guards that specifically catch the bug classes found during this release: cross-provider routing leaks, the `--cloud` filter leaking other clouds' findings, and crashes on non-AWS findings in text/SARIF output

## Scope — read this before you upgrade

**ML risk scoring is AWS-only.** The XGBoost model was trained exclusively on AWS breach patterns; Azure and GCP findings are rule-based only. They carry an explicit `ml_prediction: "N/A"` placeholder rather than a fabricated score - we chose not to reuse the AWS model's output on cloud types it was never trained to evaluate.

**GCP coverage is v1, not full parity.** 22 of the eventual 50 patterns are implemented, chosen for real-world signal rather than padding the count. AWS and Azure are both at full 50-pattern parity. See the README's Coverage Summary for the exact breakdown by domain (network/storage/IAM/secrets/monitoring).

**ML accuracy: read both numbers, not just one.** The retrained model scores 98.11% on a 53-sample held-out test set. 5-fold cross-validation on the full 265-sample training corpus shows a mean of **62.26%** (range 52.8%–73.6%). We're surfacing both in the README rather than leading with the headline test-set number alone — the training corpus is small enough that a single test split can vary substantially, and growing it is tracked as follow-up work.

## What changed under the hood

- `src/rules/security_rules.py` → `src/rules/aws_security_rules.py`, alongside new `azure_security_rules.py` and `gcp_security_rules.py`
- New `src/rules/__init__.py` registry (`RULE_ENGINES`) and `src/scanner/provider_detector.py` (resource-type prefix → cloud)
- `analyzer.py`: per-resource routing, ML gated to AWS, `cloud_breakdown` added to scan results
- `sarif_formatter.py`: `cloud` and `security-severity` properties added to every rule and result
- `cli.py`: `--cloud` flag; fixed a `KeyError` crash on non-AWS findings in `--format text` (bracket-access on `ml_risk_score`, which didn't exist for non-AWS issues); fixed `--version` requiring a `PATH` argument it shouldn't have needed; fixed `--help` not showing the tool name
- CI (`ci-cd.yml`): per-cloud, mixed-provider, and SARIF-cloud-tagging regression tests; new `examples/vulnerable-azure/` and `examples/vulnerable-gcp/` fixtures
- ML model retrained and pinned in git (previous shipped `.pkl` was stale - measured 84.9% before rebuild, 98.11% after)

## Known issue (non-blocking)

`no_versioning` (an existing AWS rule, pre-dating this release) can throw on resources where the `versioning` property is HCL2-parsed as a single-item list rather than a dict. The error is caught by the analyzer's per-rule exception handling - it doesn't crash the scan - but it does mean that rule silently produces no finding on resources shaped that way. Tracked for a follow-up patch.

## Upgrading

- GitHub Action: bump `uses: JashwanthMU/TerraSecure@v2.0.0` → `@v2.1.0`
- If you were manually chaining SARIF upload, note the corrected pattern in the README - the action now exposes `steps.<id>.outputs.sarif-file` for use with `github/codeql-action/upload-sarif`
- No CLI flags were removed or renamed; `--cloud` is additive and optional (defaults to scanning all detected clouds, matching pre-2.1.0 AWS-only behavior for AWS-only repos)

---

**Full diff:** [`v2.0.0...v2.1.0`](https://github.com/JashwanthMU/TerraSecure/compare/v2.0.0...v2.1.0)