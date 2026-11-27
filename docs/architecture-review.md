# Outpost architecture review

## Data flow

| Path | Access and trust boundary |
|---|---|
| Browser → public load balancer → Traefik → Tasky | Traefik terminates HTTPS. Port 80 serves the certificate challenge and redirects other requests. Network policy admits web traffic from the ingress controller. Two Tasky pods run on the dedicated web pool. |
| Tasky → MongoDB | Pods resolve the VM's private DNS name and connect on TCP 27017. Tasky authenticates to MongoDB with its application account and scopes todo operations to the signed-in user. This connection currently carries plaintext inside the virtual network. |
| MongoDB VM → Blob Storage | A scheduled backup uses the VM identity to create backup objects through a private endpoint. Container-scoped write access and conditional uploads limit what the writer can do. Storage uses a customer-managed key in Key Vault in the final state. |
| Evidence pod → Blob Storage | The reader exchanges its projected workload identity token for Azure access. Its separate container-scoped reader grant permits listing and reading. It resolves the private endpoint and checksums the newest archive. Tasky has neither this grant nor a Kubernetes API token after remediation. |
| Operators and pipelines → control plane | Authorized IP ranges restrict direct Kubernetes API access. Reviewed workflows authenticate with OIDC and use ARM Run Command for cluster and guest operations. The publisher writes scanned images to the registry and AKS pulls the selected digests. Control-plane audit events, service diagnostics and Activity Log alerts provide evidence independently of the application. |

## Further hardening

1. Enable TLS between Tasky and MongoDB. Issue a certificate for the private DNS name, deploy the issuing CA to clients, verify hostname checks, then require TLS on the server.
2. Upgrade the guest OS and MongoDB to supported releases. Rehearse restoring a backup and validate application reads and writes before cutover.
3. Treat the password hashes in the previously public backup as disclosed. Force password resets for affected application users and invalidate their sessions. Closing Blob access cannot recall a downloaded copy.
4. Move the database subnet to deny-by-default egress after measuring its dependencies. Retain backup, DNS, management, update and monitoring paths, then verify backup and restore.
5. Add an NSG to the integrated API subnet. Limit application traffic to the required node sources and verify AKS platform traffic, cluster health and Run Command before enforcing the rules.
6. Move ACR to Premium for Private Link, provide a private network path for publishing and pulls, then disable its public endpoint.
7. Remove the backup storage firewall's trusted-services bypass after inventorying dependencies and verifying that backup, reader, monitoring and key operations still work.
