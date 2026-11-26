# Outpost remediation runbook

This repository's `main` branch describes the **remediated (Outpost) state**. Merging the
Outpost change starts a one-way transition: Pipeline 1 refuses the Phase-1 `closed`,
`waiver` and `public` stages (Terraform variable validation, the workflow input list,
`plan-apply.sh` and `plan_gate.check_stage`). The intentionally weak baseline stays
reproducible from the commit before the merge.

## Before you start

1. Capture the Phase-1 evidence first. After the merge, no pipeline recreates the
   weak state.
2. Set the `infra` environment secret `AKS_API_HOME_CIDR` to the operator's home public
   IPv4 address as a `/32`. Every Pipeline 1 plan needs it, and Terraform rejects
   private, reserved, documentation and wider ranges.
3. Tag the cluster and VM `lab-keep-running=true`, and don't run steps across the
   nightly stop at 00:00 Israel time.

## Run order

Run every workflow from `main`. Start it as one owner and approve it as the other.
Each step can be re-run, and each stops with a numbered, labelled failure.

| # | Workflow and input | What it does | Success looks like |
|---|---|---|---|
| 1 | **Pipeline 1 - Azure infrastructure**, `backup_stage=outpost`, `target=full` | One scanned plan: backup account private-only, anonymous access off, Key Vault CMK `backup-cmk` via `id-backup-cmk`; container private; exemption `wiz-public-backup-baseline` deleted; `id-mongo` gets only **Lab Backup Writer** on the container (VM Contributor and Blob Data Contributor removed); VM public IP and Internet SSH rule removed, TCP 22 denied; AKS API limited to the home `/32` | `Applied the scanned full plan for backup stage outpost.` |
| 2 | **Pipeline 1 - Outpost VM and evidence**, `mitigate-cves` | Run Command applies both CVE mitigations, versions unchanged: zlib network compression off (CVE-2025-14847) and `algif_aead` blocked (CVE-2026-31431). It restarts `mongod` only when needed, never during a backup | `exitCode=0 (ok)` |
| 3 | Same workflow, `reboot-and-verify-cves` (or `verify-cves` after the next nightly stop and start) | Proves that both mitigations survive a reboot | `exitCode=0 (ok)` |
| 4 | Same workflow, `backup-now`, about 10 minutes after step 1 so RBAC can propagate | Runs the daily backup once with the write-only role over the private endpoint (both Put Blob requests must return HTTP 201) | `exitCode=0 (ok)` |
| 5 | **Pipeline 1 cluster setup**, `mode=outpost` | On one running web pod, its own token is checked before and after `wiz-web-baseline` is deleted. Sets `wiz-evidence/outpost-web-phase` to `outpost` | `before allowed`, `after denied` on the same pod UID |
| 6 | **Pipeline 2 release** | Rolls out web with `automountServiceAccountToken: false`. Its deploy guard refuses to run while a web pod is still allowed (that is, before step 5). Verify checks that no token is projected and that the marker check finds no credential | `rollout ready`, `match` |
| 7 | **Pipeline 1 cluster setup**, `mode=reader` | Rolls out the backup reader, then runs it once: it lists the container and downloads and checksums the newest backup through the private endpoint. It refuses any public Blob address | `backup verified privately` |
| 8 | **Pipeline 1 - Outpost VM and evidence**, `evidence` | Read-only ARM readback of every control, plus an anonymous list request from the hosted runner | Eight `PASS` lines, with the anonymous request refused |

Manual proof of the API restriction: `kubectl` works directly from home, and a direct
attempt from a second network fails at the network layer. `az aks command invoke` keeps
working from anywhere, because it goes through ARM.

## Failure and rollback

- **Terraform (step 1).** The saved-plan gate refuses any plan that reopens a control:
  public storage, any policy exemption, a VM public IP, an inbound SSH allow, the
  retired VM roles, or an AKS API that isn't one public `/32` plus VNet Integration.
  If the apply stops partway, fix the cause and re-run step 1. The plan contains only
  the remaining changes. If the CMK update is rejected, check that `id-backup-cmk` still
  holds Key Vault Crypto Service Encryption User on `backup-cmk`.
- **No API access from home.** Your public IP changed. Update `AKS_API_HOME_CIDR` and
  re-run step 1. Pipelines aren't affected.
- **VNet Integration unavailable (rebuilds only).** Add the NAT gateway's public `/32`
  (`pip-nat`) as a second authorized range in a reviewed change to `infra/aks.tf` and
  `plan_gate.py`. It is the egress of the node and DB subnets only.
- **Exit 23 in step 2.** `algif_aead` is in use. Run step 3: the block rule is already
  in place, so the module doesn't load after the reboot.
- **Exit 45 in step 6.** Run step 5 first.
- **Code rollback.** Revert the Outpost merge in a reviewed PR. Phase-1 stages then
  become plannable again, through the same reviewers and gates.
