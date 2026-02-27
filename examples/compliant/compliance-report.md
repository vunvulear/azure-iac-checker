# Azure IaC Compliance Report

**Scan Date:** 2026-02-27 17:58:53 UTC
**Path Scanned:** `examples/compliant`
**Files Scanned:** 1
**Rules Evaluated:** 35
**Severity Threshold:** High

---

## Executive Summary

| Status | Count |
|--------|-------|
| ✅ Passed | 29 |
| ❌ Failed | 6 |
| ⏭️ Skipped/Suppressed | 0 |
| **Total** | **35** |

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 3 |
| 🔵 Low | 0 |

---

## Results by Domain

### WAF — Reliability (RE:01–RE:10)
✅ 2 passed | ❌ 0 failed

### WAF — Security (SE:01–SE:12)
❌ 7 passed | ❌ 2 failed

### WAF — Cost Optimization (CO:01–CO:14)
✅ 4 passed | ❌ 0 failed

### WAF — Operational Excellence (OE:01–OE:11)
❌ 1 passed | ❌ 2 failed

### WAF — Performance Efficiency (PE:01–PE:12)
✅ 1 passed | ❌ 0 failed

### WAF — Service Guides
✅ 1 passed | ❌ 0 failed

### CAF — Naming Conventions
✅ 6 passed | ❌ 0 failed

### CAF — Tagging Strategy
✅ 6 passed | ❌ 0 failed

### CAF — Landing Zone & Subscription
✅ 1 passed | ❌ 0 failed

### CAF — Governance & Policy
❌ 0 passed | ❌ 2 failed

---

## Findings

### 🟠 High

#### WAF-SEC-008 — Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR)

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:06 |
| **Severity** | 🟠 High |
| **File** | `examples\compliant\main.tf:36` |
| **Resource** | `azurerm_storage_account.main` |
| **Description** | Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR) |
| **Recommendation** | Create azurerm_private_endpoint resources for PaaS services. Disable public network access where possible. |
| **Documentation** | [SE:06](https://learn.microsoft.com/en-us/azure/well-architected/security/networking) |

#### WAF-SEC-008 — Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR)

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | SE:06 |
| **Severity** | 🟠 High |
| **File** | `examples\compliant\main.tf:59` |
| **Resource** | `azurerm_key_vault.main` |
| **Description** | Private endpoints used for PaaS services (Storage, SQL, Key Vault, ACR) |
| **Recommendation** | Create azurerm_private_endpoint resources for PaaS services. Disable public network access where possible. |
| **Documentation** | [SE:06](https://learn.microsoft.com/en-us/azure/well-architected/security/networking) |

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

#### WAF-OPS-010 — Diagnostic settings and logging enabled on all resources that support them

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | OE:07 |
| **Severity** | 🟡 Medium |
| **File** | `examples\compliant\main.tf:36` |
| **Resource** | `azurerm_storage_account.main` |
| **Description** | Diagnostic settings and logging enabled on all resources that support them |
| **Recommendation** | Create azurerm_monitor_diagnostic_setting resources for each service that supports diagnostics. Send logs to a centralized Log Analytics workspace. |
| **Documentation** | [OE:07](https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/observability) |

#### CAF-GOV-013 — Resource locks defined on critical production resources

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | RM01 |
| **Severity** | 🟡 Medium |
| **File** | `examples\compliant\main.tf:59` |
| **Resource** | `azurerm_key_vault.main` |
| **Description** | Resource locks defined on critical production resources |
| **Recommendation** | Add azurerm_management_lock with lock_level = 'CanNotDelete' on production databases, key vaults, and hub networking resources. |
| **Documentation** | [RM01](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/govern/document-cloud-governance-policies) |

#### WAF-OPS-010 — Diagnostic settings and logging enabled on all resources that support them

| Field | Value |
|-------|-------|
| **WAF/CAF Reference** | OE:07 |
| **Severity** | 🟡 Medium |
| **File** | `examples\compliant\main.tf:59` |
| **Resource** | `azurerm_key_vault.main` |
| **Description** | Diagnostic settings and logging enabled on all resources that support them |
| **Recommendation** | Create azurerm_monitor_diagnostic_setting resources for each service that supports diagnostics. Send logs to a centralized Log Analytics workspace. |
| **Documentation** | [OE:07](https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/observability) |

---

## Passed Rules
<details>
<summary>Click to expand (29 rules passed)</summary>

| Rule ID | WAF/CAF Ref | Description |
|---------|-------------|-------------|
| CAF-LZ-003 | Resource Org | Resource groups organized by lifecycle and function — not monolithic single-RG |
| CAF-NAME-001 | Naming | Resource names follow CAF naming convention |
| CAF-NAME-001 | Naming | Resource names follow CAF naming convention |
| CAF-NAME-001 | Naming | Resource names follow CAF naming convention |
| CAF-NAME-004 | Naming | Names within Azure character limits and allowed character sets |
| CAF-NAME-004 | Naming | Names within Azure character limits and allowed character sets |
| CAF-NAME-004 | Naming | Names within Azure character limits and allowed character sets |
| CAF-TAG-009 | Validation | Tag values follow defined allowed-value lists |
| CAF-TAG-009 | Validation | Tag values follow defined allowed-value lists |
| CAF-TAG-009 | Validation | Tag values follow defined allowed-value lists |
| CAF-TAG-012 | Mandatory | All taggable resources have minimum mandatory tags: env, owner, costCenter, app |
| CAF-TAG-012 | Mandatory | All taggable resources have minimum mandatory tags: env, owner, costCenter, app |
| CAF-TAG-012 | Mandatory | All taggable resources have minimum mandatory tags: env, owner, costCenter, app |
| WAF-COST-001 | CO:01 | Tags for cost allocation present — costCenter, environment, owner |
| WAF-COST-001 | CO:01 | Tags for cost allocation present — costCenter, environment, owner |
| WAF-COST-001 | CO:01 | Tags for cost allocation present — costCenter, environment, owner |
| WAF-COST-007 | CO:07 | Oversized SKUs detected for dev/test environments |
| WAF-OPS-005 | OE:05 | Terraform state stored remotely (Azure Storage backend with locking) |
| WAF-PERF-011 | PE:08 | Storage account performance tier appropriate — Premium for IOPS-intensive, Standard for general use |
| WAF-REL-009 | RE:07 | Soft-delete enabled on Key Vault |
| WAF-REL-013 | RE:09 | Disaster recovery configuration present — paired regions, geo-redundant backups |
| WAF-SEC-012 | SE:07 | Encryption in transit enforced — min_tls_version = TLS1_2 |
| WAF-SEC-014 | SE:07 | Key Vault configured with RBAC authorization, soft-delete, and purge protection |
| WAF-SEC-016 | SE:08 | Storage accounts disallow public blob access |
| WAF-SEC-017 | SE:08 | Storage accounts enforce HTTPS-only transfer |
| WAF-SEC-019 | SE:09 | No hardcoded secrets, passwords, keys, or connection strings in .tf or .tfvars |
| WAF-SEC-019 | SE:09 | No hardcoded secrets, passwords, keys, or connection strings in .tf or .tfvars |
| WAF-SEC-019 | SE:09 | No hardcoded secrets, passwords, keys, or connection strings in .tf or .tfvars |
| WAF-SVC-010 | SE:06 | Storage account firewall enabled — default_action = Deny |

</details>
