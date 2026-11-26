# Outpost remediation runbook

Use this runbook when the Owner resumes the lab. The Outpost branch retires the Phase 1 stages. Preserve the baseline screenshots, working release and backup evidence before the transition.

## Preparation

* Use reviewed workflows on main with the protected infra or release environment. Keep the cluster and VM running throughout the transition and avoid the nightly stop.
* Set the infra secret `AKS_API_HOME_CIDR` to the operator's public IPv4 /32. Leave the optional infra variable `AKS_API_ALLOW_NAT` unset or false. Set it to true only if a system client needs the NAT path. The plan gate then also admits the refreshed NAT public IP as a /32.
* Use **target=full** for every infrastructure run on the live lab. The RBAC moved block carries the existing CMK grant to its new Terraform address. A partial bootstrap target can exclude one end of that move.
* For a fresh deployment, use a separately reviewed baseline bootstrap to seed the identities and grant scopes in state before Outpost. The gate requires known principal and scope IDs for the vault, both keys, subnets, ingress IP, kubelet identity, cluster, VM, container and registry. The partial workflow targets maintain already-seeded non-live environments.
* Review the lab deadline in `infra/lab-expiry.txt`. Edit that single ISO date when the Owner confirms a new deadline. The scanner policies, saved-plan exceptions, resource tags and Automation expiry use it. Outpost deletes the baseline exemption. Run `bash infra/pipeline/scan-iac.sh` to check the effective scanner policies.
* After merge and **before step 1**, run **Pipeline 1 - Outpost VM and evidence** with `step=report`. Save the before table from the job summary. Failed baseline controls are expected. A missing permission or unavailable service also fails its check and needs investigation.

## Run order

| Step | Workflow or operator | Evidence to retain |
|---|---|---|
| 1 | **Pipeline 1 - Azure infrastructure**, `backup_stage=outpost`, `target=full`. For existing public storage, step A closes public networking and anonymous access using the current service-managed encryption. Step B scans and applies a second saved plan to attach the backup CMK. Private storage goes directly to B on retry. | Verify both stages, the closed container, and the final Key Vault CMK. A successful A alone is partial remediation. Review the planned addresses and actions. Any replacement stops the gate. |
| 1a | Immediately run **Pipeline 1 cluster setup**, `mode=api-probe`, before further guest or workload work. | One ARM Run Command must list system pods and successfully exec in a running container. Confirm direct access from home separately. If the probe fails, stop and investigate the system path. |
| 1b | **Owner** removes the Resource Policy Contributor grant for `takehome-id` at its assigned scope after step 1 has deleted the exemption. Check for inherited or overlapping grants. | Allow RBAC propagation. The final report checks whether the pipeline principal can still write an exemption on the backup account. |
| 2 | **Pipeline 1 - Outpost VM and evidence**, `mitigate-cves`, then `inspect`. | Verify SSH service shutdown, guest OS, database version and listener summary through Run Command. Applicable mitigations disable MongoDB zlib compression and the affected kernel module. |
| 3 | Same workflow, `reboot-and-verify-cves`, or `verify-cves` after a scheduled restart. | Both applicable mitigations survive restart and SSH remains disabled. Retain any version-specific “not applicable” results. |
| 4 | Same workflow, `backup-now`, after the container-scoped role change propagates. | The daily backup succeeds over the private endpoint with the restricted VM identity. |
| 5 | **Pipeline 1 cluster setup**, `mode=outpost`. | Save the allowed and denied decisions for the same pod UID. The workflow records revocation, rotates the web pods off the projected token and closes their API egress. If a later step fails, retain the first run's partial proof. |
| 6 | **Pipeline 2 release**. | Verify the scanned digest, web-node placement and token-free rollout. An inconclusive credential check on an old token-bearing pod blocks this release. |
| 7 | **Pipeline 1 cluster setup**, `mode=reader`. | Retain the validated archive count, newest backup name, its SHA-256 and the Blob private endpoint address from the reader. Compare the archive with step 4. |
| 8 | **Pipeline 1 - Outpost VM and evidence**, `step=report`. | Save the after table beside the before table. Require all ten controls to pass, including customer-managed encryption, denial of anonymous listing, runner-to-API isolation and removal of exemption-write permission. |

## Recovery

* **CMK fails in step B.** Verify public access is still disabled. Check the storage identity, its Crypto Service Encryption User grant on the backup key and the vault trusted-services path. Repeat the full run after correcting the cause. The gate refuses to remove a CMK or rerun step A on private storage.
* **API probe fails.** Confirm the authorized home range and VNet Integration. If the NAT path is needed, use the reviewed optional NAT setting, repeat the full run and repeat the probe. Never add the runner's public range.
* **Proof interrupted.** Preserve the first run's validated partial output. Inspect the binding, pod UID and phase before retrying. An already-revoked credential cannot demonstrate its original access a second time.
* **Unexpected delete or replacement.** Stop and inspect the proposed addresses against the reviewed migration. Keep the live resources in place.
