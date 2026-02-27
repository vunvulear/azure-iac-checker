# Azure IaC Compliance Report

**Scan Date:** 2026-02-27 17:58:48 UTC
**Path Scanned:** `examples/non-compliant`
**Files Scanned:** 1
**Rules Evaluated:** 80
**Severity Threshold:** High

---

## Executive Summary

| Status | Count |
|--------|-------|
| ✅ Passed | 35 |
| ❌ Failed | 44 |
| ⏭️ Skipped/Suppressed | 1 |
| **Total** | **80** |

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 28 |
| 🟡 Medium | 15 |
| 🔵 Low | 0 |

---

## Results by Domain

### WAF — Reliability (RE:01–RE:10)
❌ 0 passed | ❌ 4 failed

### WAF — Security (SE:01–SE:12)
❌ 7 passed | ❌ 11 failed

### WAF — Cost Optimization (CO:01–CO:14)
❌ 4 passed | ❌ 6 failed

### WAF — Operational Excellence (OE:01–OE:11)
❌ 0 passed | ❌ 6 failed

### WAF — Performance Efficiency (PE:01–PE:12)
✅ 1 passed | ❌ 0 failed

### WAF — Service Guides
❌ 0 passed | ❌ 4 failed

### CAF — Naming Conventions
❌ 14 passed | ❌ 1 failed

### CAF — Tagging Strategy
❌ 8 passed | ❌ 5 failed

### CAF — Landing Zone & Subscription
✅ 1 passed | ❌ 0 failed

### CAF — Networking
❌ 0 passed | ❌ 1 failed

### CAF — Identity & Access
❌ 0 passed | ❌ 2 failed

### CAF — Governance & Policy
❌ 0 passed | ❌ 4 failed

---

## Findings

### 🔴 Critical

#### WAF-SEC-019 — Hardcoded secret found in attribute 'administrator_login_password'

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:09 |
| **Severity** | 🔴 Critical |
| **File** | `examples\non-compliant\main.tf:21` |
| **Resource** | `azurerm_mssql_server.bad` |
| **Description** | Hardcoded secret found in attribute 'administrator_login_password' |
| **Recommendation** | Use Azure Key Vault references, sensitive variables, or environment variables. Never store secrets in Terraform files. |
| **Documentation** | [SE:09](https://learn.microsoft.com/en-us/azure/well-architected/security/application-secrets) |

### 🟠 High

#### CAF-NAME-001 — Naming violation for 'my-resource-group': Expected CAF prefix 'rg' for azurerm_resource_group, got 'my'

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | Naming |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:6` |
| **Resource** | `azurerm_resource_group.bad` |
| **Description** | Naming violation for 'my-resource-group': Expected CAF prefix 'rg' for azurerm_resource_group, got 'my' |
| **Recommendation** | Follow the pattern: <abbreviation>-<workload>-<env>-<region>-<instance>. See https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations |
| **Documentation** | [Naming](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming) |

#### CAF-TAG-012 — No tags block defined — missing mandatory tags: env, owner, costCenter, app

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | Mandatory |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:6` |
| **Resource** | `azurerm_resource_group.bad` |
| **Description** | No tags block defined — missing mandatory tags: env, owner, costCenter, app |
| **Recommendation** | Add mandatory tags to all taggable resources. Minimum set: env, owner, costCenter, app. Configure the mandatory set in .iac-checker.yaml. |
| **Documentation** | [Mandatory](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-tagging) |

#### WAF-SEC-012 — Encryption in transit enforced — min_tls_version = TLS1_2 — attribute `min_tls_version` is missing

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:07 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:12` |
| **Resource** | `azurerm_storage_account.bad` |
| **Description** | Encryption in transit enforced — min_tls_version = TLS1_2 — attribute `min_tls_version` is missing |
| **Recommendation** | Set min_tls_version = 'TLS1_2' on all applicable resources. |
| **Documentation** | [SE:07](https://learn.microsoft.com/en-us/azure/well-architected/security/encryption) |

#### WAF-SEC-016 — Storage accounts disallow public blob access — attribute `allow_nested_items_to_be_public` is missing

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:08 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:12` |
| **Resource** | `azurerm_storage_account.bad` |
| **Description** | Storage accounts disallow public blob access — attribute `allow_nested_items_to_be_public` is missing |
| **Recommendation** | Set allow_nested_items_to_be_public = false on storage accounts. |
| **Documentation** | [SE:08](https://learn.microsoft.com/en-us/azure/well-architected/security/networking) |

#### WAF-SEC-017 — Storage accounts enforce HTTPS-only transfer — attribute `enable_https_traffic_only` is missing

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:08 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:12` |
| **Resource** | `azurerm_storage_account.bad` |
| **Description** | Storage accounts enforce HTTPS-only transfer — attribute `enable_https_traffic_only` is missing |
| **Recommendation** | Set enable_https_traffic_only = true on storage accounts. |
| **Documentation** | [SE:08](https://learn.microsoft.com/en-us/azure/well-architected/security/networking) |

#### WAF-SVC-010 — Storage account firewall enabled — default_action = Deny — attribute `network_rules.default_action` is missing

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:06 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:12` |
| **Resource** | `azurerm_storage_account.bad` |
| **Description** | Storage account firewall enabled — default_action = Deny — attribute `network_rules.default_action` is missing |
| **Recommendation** | Configure network_rules with default_action = 'Deny' and whitelist necessary IPs/subnets. |
| **Documentation** | [SE:06](https://learn.microsoft.com/en-us/azure/well-architected/service-guides/storage-accounts) |

#### WAF-REL-013 — Disaster recovery configuration present — paired regions, geo-redundant backups

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | RE:09 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:12` |
| **Resource** | `azurerm_storage_account.bad` |
| **Description** | Disaster recovery configuration present — paired regions, geo-redundant backups |
| **Recommendation** | Configure geo-redundant storage (GRS/GZRS), SQL geo-replication, or Recovery Services Vault with cross-region replication. |
| **Documentation** | [RE:09](https://learn.microsoft.com/en-us/azure/well-architected/reliability/disaster-recovery) |

#### WAF-SEC-008 — Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR)

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:06 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:12` |
| **Resource** | `azurerm_storage_account.bad` |
| **Description** | Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR) |
| **Recommendation** | Create azurerm_private_endpoint resources for PaaS services. Disable public network access where possible. |
| **Documentation** | [SE:06](https://learn.microsoft.com/en-us/azure/well-architected/security/networking) |

#### CAF-TAG-012 — No tags block defined — missing mandatory tags: env, owner, costCenter, app

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | Mandatory |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:12` |
| **Resource** | `azurerm_storage_account.bad` |
| **Description** | No tags block defined — missing mandatory tags: env, owner, costCenter, app |
| **Recommendation** | Add mandatory tags to all taggable resources. Minimum set: env, owner, costCenter, app. Configure the mandatory set in .iac-checker.yaml. |
| **Documentation** | [Mandatory](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-tagging) |

#### WAF-SEC-012 — Encryption in transit enforced — min_tls_version = TLS1_2 — attribute `min_tls_version` is missing

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:07 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:21` |
| **Resource** | `azurerm_mssql_server.bad` |
| **Description** | Encryption in transit enforced — min_tls_version = TLS1_2 — attribute `min_tls_version` is missing |
| **Recommendation** | Set min_tls_version = 'TLS1_2' on all applicable resources. |
| **Documentation** | [SE:07](https://learn.microsoft.com/en-us/azure/well-architected/security/encryption) |

#### WAF-SEC-008 — Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR)

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:06 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:21` |
| **Resource** | `azurerm_mssql_server.bad` |
| **Description** | Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR) |
| **Recommendation** | Create azurerm_private_endpoint resources for PaaS services. Disable public network access where possible. |
| **Documentation** | [SE:06](https://learn.microsoft.com/en-us/azure/well-architected/security/networking) |

#### WAF-SVC-009 — SQL Database configured with private endpoint — no public access for production

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:06 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:21` |
| **Resource** | `azurerm_mssql_server.bad` |
| **Description** | SQL Database configured with private endpoint — no public access for production |
| **Recommendation** | Set public_network_access_enabled = false on azurerm_mssql_server and create an azurerm_private_endpoint for the SQL server. |
| **Documentation** | [SE:06](https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-sql-database-well-architected-framework) |

#### CAF-TAG-012 — Missing mandatory tags: owner, costCenter, app

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | Mandatory |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:21` |
| **Resource** | `azurerm_mssql_server.bad` |
| **Description** | Missing mandatory tags: owner, costCenter, app |
| **Recommendation** | Add mandatory tags to all taggable resources. Minimum set: env, owner, costCenter, app. Configure the mandatory set in .iac-checker.yaml. |
| **Documentation** | [Mandatory](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-tagging) |

#### WAF-REL-009 — Soft-delete enabled on Key Vault

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | RE:07 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:35` |
| **Resource** | `azurerm_key_vault.bad` |
| **Description** | Soft-delete enabled on Key Vault |
| **Recommendation** | Set soft_delete_retention_days (default 90) and purge_protection_enabled = true on Key Vault. |
| **Documentation** | [RE:07](https://learn.microsoft.com/en-us/azure/well-architected/reliability/self-preservation) |

#### WAF-SEC-008 — Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR)

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:06 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:35` |
| **Resource** | `azurerm_key_vault.bad` |
| **Description** | Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR) |
| **Recommendation** | Create azurerm_private_endpoint resources for PaaS services. Disable public network access where possible. |
| **Documentation** | [SE:06](https://learn.microsoft.com/en-us/azure/well-architected/security/networking) |

#### WAF-SEC-014 — Key Vault configured with RBAC authorization, soft-delete, and purge protection

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:07 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:35` |
| **Resource** | `azurerm_key_vault.bad` |
| **Description** | Key Vault configured with RBAC authorization, soft-delete, and purge protection |
| **Recommendation** | Set enable_rbac_authorization = true, soft_delete_retention_days >= 7, and purge_protection_enabled = true on Key Vault. |
| **Documentation** | [SE:07](https://learn.microsoft.com/en-us/azure/well-architected/security/encryption) |

#### CAF-IAM-004 — Managed identities used for service-to-service authentication

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | Identity |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:53` |
| **Resource** | `azurerm_kubernetes_cluster.bad` |
| **Description** | Managed identities used for service-to-service authentication |
| **Recommendation** | Add an identity {} block with type = 'SystemAssigned' or 'UserAssigned' to enable managed identity on the resource. |
| **Documentation** | [Identity](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/identity-access) |

#### WAF-REL-002 — Resources deployed across multiple Availability Zones where supported

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | RE:05 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:53` |
| **Resource** | `azurerm_kubernetes_cluster.bad` |
| **Description** | Resources deployed across multiple Availability Zones where supported |
| **Recommendation** | Set the 'zones' attribute to deploy across multiple Availability Zones. For VMs use 'zone', for VMSS/AKS use 'zones'. |
| **Documentation** | [RE:05](https://learn.microsoft.com/en-us/azure/well-architected/reliability/redundancy) |

#### WAF-SVC-003 — AKS node pools spread across Availability Zones

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | RE:05 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:53` |
| **Resource** | `azurerm_kubernetes_cluster.bad` |
| **Description** | AKS node pools spread across Availability Zones |
| **Recommendation** | Set availability_zones or zones on default_node_pool and additional node pools. |
| **Documentation** | [RE:05](https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-kubernetes-service) |

#### WAF-REL-002 — Resources deployed across multiple Availability Zones where supported

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | RE:05 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:74` |
| **Resource** | `azurerm_linux_virtual_machine.bad` |
| **Description** | Resources deployed across multiple Availability Zones where supported |
| **Recommendation** | Set the 'zones' attribute to deploy across multiple Availability Zones. For VMs use 'zone', for VMSS/AKS use 'zones'. |
| **Documentation** | [RE:05](https://learn.microsoft.com/en-us/azure/well-architected/reliability/redundancy) |

#### CAF-TAG-012 — No tags block defined — missing mandatory tags: env, owner, costCenter, app

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | Mandatory |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:107` |
| **Resource** | `azurerm_network_security_rule.allow_all` |
| **Description** | No tags block defined — missing mandatory tags: env, owner, costCenter, app |
| **Recommendation** | Add mandatory tags to all taggable resources. Minimum set: env, owner, costCenter, app. Configure the mandatory set in .iac-checker.yaml. |
| **Documentation** | [Mandatory](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-tagging) |

#### CAF-NET-004 — NSG Allow rule uses wildcard (*) — source='*', dest='*', ports='*/*'

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | Segmentation |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:107` |
| **Resource** | `azurerm_network_security_rule.allow_all` |
| **Description** | NSG Allow rule uses wildcard (*) — source='*', dest='*', ports='*/*' |
| **Recommendation** | Replace wildcard (*) source, destination, and port ranges with specific CIDR blocks, service tags, or port numbers. |
| **Documentation** | [Segmentation](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-landing-zone-network-segmentation) |

#### CAF-IAM-001 — Role 'Owner' assigned at subscription scope

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | RBAC |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:122` |
| **Resource** | `azurerm_role_assignment.bad_rbac` |
| **Description** | Role 'Owner' assigned at subscription scope |
| **Recommendation** | Avoid Owner or Contributor at subscription scope. Scope RBAC assignments to resource group or resource level where possible. |
| **Documentation** | [RBAC](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/identity-access) |

#### WAF-SEC-012 — Encryption in transit enforced — min_tls_version = TLS1_2 — attribute `min_tls_version` is missing

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:07 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:130` |
| **Resource** | `azurerm_mssql_server.legacy` |
| **Description** | Encryption in transit enforced — min_tls_version = TLS1_2 — attribute `min_tls_version` is missing |
| **Recommendation** | Set min_tls_version = 'TLS1_2' on all applicable resources. |
| **Documentation** | [SE:07](https://learn.microsoft.com/en-us/azure/well-architected/security/encryption) |

#### WAF-SEC-008 — Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR)

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:06 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:130` |
| **Resource** | `azurerm_mssql_server.legacy` |
| **Description** | Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR) |
| **Recommendation** | Create azurerm_private_endpoint resources for PaaS services. Disable public network access where possible. |
| **Documentation** | [SE:06](https://learn.microsoft.com/en-us/azure/well-architected/security/networking) |

#### WAF-SVC-009 — SQL Database configured with private endpoint — no public access for production

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:06 |
| **Severity** | 🟠 High |
| **File** | `examples\non-compliant\main.tf:130` |
| **Resource** | `azurerm_mssql_server.legacy` |
| **Description** | SQL Database configured with private endpoint — no public access for production |
| **Recommendation** | Set public_network_access_enabled = false on azurerm_mssql_server and create an azurerm_private_endpoint for the SQL server. |
| **Documentation** | [SE:06](https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-sql-database-well-architected-framework) |

#### WAF-OPS-005 — Terraform state stored remotely (Azure Storage backend with locking)

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | OE:05 |
| **Severity** | 🟠 High |
| **File** | `terraform {}:0` |
| **Resource** | `terraform.backend` |
| **Description** | Terraform state stored remotely (Azure Storage backend with locking) |
| **Recommendation** | Configure a backend 'azurerm' block in the terraform {} config to store state in Azure Storage with state locking enabled. |
| **Documentation** | [OE:05](https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/infrastructure-as-code-design) |

#### CAF-GOV-012 — Data residency — Azure Policy restricts resource deployment to approved regions

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | DG02 |
| **Severity** | 🟠 High |
| **File** | `global:0` |
| **Resource** | `governance.data_residency_policy` |
| **Description** | Data residency — Azure Policy restricts resource deployment to approved regions |
| **Recommendation** | Define an Azure Policy assignment (azurerm_policy_assignment) that restricts resource deployment to approved Azure regions using the 'Allowed locations' built-in policy. |
| **Documentation** | [DG02](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/govern/document-cloud-governance-policies) |

### 🟡 Medium

#### WAF-COST-001 — Tags for cost allocation present — costCenter, environment, owner — attribute `tags.costCenter` is missing

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | CO:01 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:6` |
| **Resource** | `azurerm_resource_group.bad` |
| **Description** | Tags for cost allocation present — costCenter, environment, owner — attribute `tags.costCenter` is missing |
| **Recommendation** | Add costCenter, environment, and owner tags to all resources for financial tracking. |
| **Documentation** | [CO:01](https://learn.microsoft.com/en-us/azure/well-architected/cost-optimization/collect-review-cost-data) |

#### WAF-COST-001 — Tags for cost allocation present — costCenter, environment, owner — attribute `tags.costCenter` is missing

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | CO:01 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:12` |
| **Resource** | `azurerm_storage_account.bad` |
| **Description** | Tags for cost allocation present — costCenter, environment, owner — attribute `tags.costCenter` is missing |
| **Recommendation** | Add costCenter, environment, and owner tags to all resources for financial tracking. |
| **Documentation** | [CO:01](https://learn.microsoft.com/en-us/azure/well-architected/cost-optimization/collect-review-cost-data) |

#### WAF-COST-007 — Oversized SKUs detected for dev/test environments

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | CO:07 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:12` |
| **Resource** | `azurerm_storage_account.bad` |
| **Description** | Oversized SKUs detected for dev/test environments |
| **Recommendation** | Use Standard SKUs for dev/test instead of Premium. Review SKU sizing against actual utilization. |
| **Documentation** | [CO:07](https://learn.microsoft.com/en-us/azure/well-architected/cost-optimization/optimize-component-costs) |

#### WAF-OPS-010 — Diagnostic settings and logging enabled on all resources that support them

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | OE:07 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:12` |
| **Resource** | `azurerm_storage_account.bad` |
| **Description** | Diagnostic settings and logging enabled on all resources that support them |
| **Recommendation** | Create azurerm_monitor_diagnostic_setting resources for each service that supports diagnostics. Send logs to a centralized Log Analytics workspace. |
| **Documentation** | [OE:07](https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/observability) |

#### CAF-GOV-013 — Resource locks defined on critical production resources

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | RM01 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:21` |
| **Resource** | `azurerm_mssql_server.bad` |
| **Description** | Resource locks defined on critical production resources |
| **Recommendation** | Add azurerm_management_lock with lock_level = 'CanNotDelete' on production databases, key vaults, and hub networking resources. |
| **Documentation** | [RM01](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/govern/document-cloud-governance-policies) |

#### WAF-COST-001 — Tags for cost allocation present — costCenter, environment, owner — attribute `tags.costCenter` is missing

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | CO:01 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:21` |
| **Resource** | `azurerm_mssql_server.bad` |
| **Description** | Tags for cost allocation present — costCenter, environment, owner — attribute `tags.costCenter` is missing |
| **Recommendation** | Add costCenter, environment, and owner tags to all resources for financial tracking. |
| **Documentation** | [CO:01](https://learn.microsoft.com/en-us/azure/well-architected/cost-optimization/collect-review-cost-data) |

#### WAF-OPS-010 — Diagnostic settings and logging enabled on all resources that support them

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | OE:07 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:21` |
| **Resource** | `azurerm_mssql_server.bad` |
| **Description** | Diagnostic settings and logging enabled on all resources that support them |
| **Recommendation** | Create azurerm_monitor_diagnostic_setting resources for each service that supports diagnostics. Send logs to a centralized Log Analytics workspace. |
| **Documentation** | [OE:07](https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/observability) |

#### CAF-TAG-009 — Tag 'env' has invalid value 'production'. Allowed: dev, prod, qa, sandbox, staging, test, uat

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | Validation |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:21` |
| **Resource** | `azurerm_mssql_server.bad` |
| **Description** | Tag 'env' has invalid value 'production'. Allowed: dev, prod, qa, sandbox, staging, test, uat |
| **Recommendation** | Ensure env tag uses one of: dev, staging, test, qa, prod. |
| **Documentation** | [Validation](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-tagging) |

#### CAF-GOV-013 — Resource locks defined on critical production resources

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | RM01 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:35` |
| **Resource** | `azurerm_key_vault.bad` |
| **Description** | Resource locks defined on critical production resources |
| **Recommendation** | Add azurerm_management_lock with lock_level = 'CanNotDelete' on production databases, key vaults, and hub networking resources. |
| **Documentation** | [RM01](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/govern/document-cloud-governance-policies) |

#### WAF-OPS-010 — Diagnostic settings and logging enabled on all resources that support them

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | OE:07 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:35` |
| **Resource** | `azurerm_key_vault.bad` |
| **Description** | Diagnostic settings and logging enabled on all resources that support them |
| **Recommendation** | Create azurerm_monitor_diagnostic_setting resources for each service that supports diagnostics. Send logs to a centralized Log Analytics workspace. |
| **Documentation** | [OE:07](https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/observability) |

#### WAF-OPS-010 — Diagnostic settings and logging enabled on all resources that support them

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | OE:07 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:53` |
| **Resource** | `azurerm_kubernetes_cluster.bad` |
| **Description** | Diagnostic settings and logging enabled on all resources that support them |
| **Recommendation** | Create azurerm_monitor_diagnostic_setting resources for each service that supports diagnostics. Send logs to a centralized Log Analytics workspace. |
| **Documentation** | [OE:07](https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/observability) |

#### WAF-COST-001 — Tags for cost allocation present — costCenter, environment, owner — attribute `tags.costCenter` is missing

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | CO:01 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:107` |
| **Resource** | `azurerm_network_security_rule.allow_all` |
| **Description** | Tags for cost allocation present — costCenter, environment, owner — attribute `tags.costCenter` is missing |
| **Recommendation** | Add costCenter, environment, and owner tags to all resources for financial tracking. |
| **Documentation** | [CO:01](https://learn.microsoft.com/en-us/azure/well-architected/cost-optimization/collect-review-cost-data) |

#### WAF-COST-001 — Tags for cost allocation present — costCenter, environment, owner — attribute `tags.costCenter` is missing

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | CO:01 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:122` |
| **Resource** | `azurerm_role_assignment.bad_rbac` |
| **Description** | Tags for cost allocation present — costCenter, environment, owner — attribute `tags.costCenter` is missing |
| **Recommendation** | Add costCenter, environment, and owner tags to all resources for financial tracking. |
| **Documentation** | [CO:01](https://learn.microsoft.com/en-us/azure/well-architected/cost-optimization/collect-review-cost-data) |

#### CAF-GOV-013 — Resource locks defined on critical production resources

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | RM01 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:130` |
| **Resource** | `azurerm_mssql_server.legacy` |
| **Description** | Resource locks defined on critical production resources |
| **Recommendation** | Add azurerm_management_lock with lock_level = 'CanNotDelete' on production databases, key vaults, and hub networking resources. |
| **Documentation** | [RM01](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/govern/document-cloud-governance-policies) |

#### WAF-OPS-010 — Diagnostic settings and logging enabled on all resources that support them

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | OE:07 |
| **Severity** | 🟡 Medium |
| **File** | `examples\non-compliant\main.tf:130` |
| **Resource** | `azurerm_mssql_server.legacy` |
| **Description** | Diagnostic settings and logging enabled on all resources that support them |
| **Recommendation** | Create azurerm_monitor_diagnostic_setting resources for each service that supports diagnostics. Send logs to a centralized Log Analytics workspace. |
| **Documentation** | [OE:07](https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/observability) |

---

## Passed Rules
<details>
<summary>Click to expand (35 rules passed)</summary>

| Rule ID | WAF/CAF Ref | Description |
|---------|-------------|-------------|
| CAF-LZ-003 | Resource Org | Resource groups organized by lifecycle and function — not monolithic single-RG |
| CAF-NAME-001 | Naming | Resource names follow CAF naming convention |
| CAF-NAME-001 | Naming | Resource names follow CAF naming convention |
| CAF-NAME-001 | Naming | Resource names follow CAF naming convention |
| CAF-NAME-001 | Naming | Resource names follow CAF naming convention |
| CAF-NAME-001 | Naming | Resource names follow CAF naming convention |
| CAF-NAME-001 | Naming | Resource names follow CAF naming convention |
| CAF-NAME-004 | Naming | Names within Azure character limits and allowed character sets |
| CAF-NAME-004 | Naming | Names within Azure character limits and allowed character sets |
| CAF-NAME-004 | Naming | Names within Azure character limits and allowed character sets |
| CAF-NAME-004 | Naming | Names within Azure character limits and allowed character sets |
| CAF-NAME-004 | Naming | Names within Azure character limits and allowed character sets |
| CAF-NAME-004 | Naming | Names within Azure character limits and allowed character sets |
| CAF-NAME-004 | Naming | Names within Azure character limits and allowed character sets |
| CAF-NAME-004 | Naming | Names within Azure character limits and allowed character sets |
| CAF-TAG-009 | Validation | Tag values follow defined allowed-value lists |
| CAF-TAG-009 | Validation | Tag values follow defined allowed-value lists |
| CAF-TAG-009 | Validation | Tag values follow defined allowed-value lists |
| CAF-TAG-009 | Validation | Tag values follow defined allowed-value lists |
| CAF-TAG-012 | Mandatory | All taggable resources have minimum mandatory tags: env, owner, costCenter, app |
| CAF-TAG-012 | Mandatory | All taggable resources have minimum mandatory tags: env, owner, costCenter, app |
| CAF-TAG-012 | Mandatory | All taggable resources have minimum mandatory tags: env, owner, costCenter, app |
| CAF-TAG-012 | Mandatory | All taggable resources have minimum mandatory tags: env, owner, costCenter, app |
| WAF-COST-001 | CO:01 | Tags for cost allocation present — costCenter, environment, owner |
| WAF-COST-001 | CO:01 | Tags for cost allocation present — costCenter, environment, owner |
| WAF-COST-001 | CO:01 | Tags for cost allocation present — costCenter, environment, owner |
| WAF-COST-001 | CO:01 | Tags for cost allocation present — costCenter, environment, owner |
| WAF-PERF-011 | PE:08 | Storage account performance tier appropriate — Premium for IOPS-intensive, Standard for general use |
| WAF-SEC-019 | SE:09 | No hardcoded secrets, passwords, keys, or connection strings in .tf or .tfvars |
| WAF-SEC-019 | SE:09 | No hardcoded secrets, passwords, keys, or connection strings in .tf or .tfvars |
| WAF-SEC-019 | SE:09 | No hardcoded secrets, passwords, keys, or connection strings in .tf or .tfvars |
| WAF-SEC-019 | SE:09 | No hardcoded secrets, passwords, keys, or connection strings in .tf or .tfvars |
| WAF-SEC-019 | SE:09 | No hardcoded secrets, passwords, keys, or connection strings in .tf or .tfvars |
| WAF-SEC-019 | SE:09 | No hardcoded secrets, passwords, keys, or connection strings in .tf or .tfvars |
| WAF-SEC-019 | SE:09 | No hardcoded secrets, passwords, keys, or connection strings in .tf or .tfvars |

</details>
