# Azure IaC Compliance Checker

A Python CLI tool that scans **Terraform**, **ARM templates**, and **Bicep** files against Azure WAF & CAF best practices and generates a Markdown compliance report.

## Table of Contents

- [Supported Formats](#supported-formats)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [Examples by Format](#examples-by-format)
  - [Terraform Example](#terraform-example)
  - [ARM Template Example](#arm-template-example)
  - [Bicep Example](#bicep-example)
- [Inline Suppressions](#inline-suppressions)
- [Exit Codes](#exit-codes)
- [Common Errors & Troubleshooting](#common-errors--troubleshooting)

---

## Supported Formats

| Format | Extensions | Parser | Notes |
|--------|-----------|--------|-------|
| **Terraform** | `.tf`, `.tfvars` | `python-hcl2` | Full HCL parsing |
| **ARM Templates** | `.json` | Built-in JSON | Auto-detected via `$schema` URL |
| **Bicep** | `.bicep` | Bicep CLI → ARM → JSON | Requires `bicep` or `az bicep` on PATH |

---

## Installation

### Prerequisites

- **Python 3.10+**
- **pip** (Python package manager)
- **Bicep CLI** *(optional)* — required only for scanning `.bicep` files. Install via `az bicep install` or download from [Azure/bicep releases](https://github.com/Azure/bicep/releases).

### Install from source

```bash
cd <project-root>

# Install production dependencies
pip install python-hcl2 PyYAML

# Install the package in editable mode
pip install -e .

# Verify installation
iac-checker --version
```

### Install dev dependencies (for running tests)

```bash
pip install -e ".[dev]"
python -m pytest tests -v
```

---

## Quick Start

```bash
# Scan all IaC formats (Terraform + ARM + Bicep) — default
iac-checker --path ./infra

# Scan only Terraform files
iac-checker --path ./infra --format terraform

# Scan only ARM and Bicep files
iac-checker --path ./infra --format arm bicep

# With custom config and output
iac-checker --path ./infra --config .iac-checker.yaml --output report.md

# Override severity threshold from CLI
iac-checker --path ./infra --severity-threshold Critical
```

---

## CLI Reference

```
usage: iac-checker [-h] --path PATH [--config CONFIG] [--output OUTPUT]
                   [--severity-threshold {Critical,High,Medium,Low}]
                   [--format {terraform,arm,bicep} ...] [--version]
```

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--path` | `-p` | **Yes** | — | Path to the IaC folder to scan |
| `--format` | `-f` | No | `terraform arm bicep` | IaC formats to scan (space-separated) |
| `--config` | `-c` | No | `.iac-checker.yaml` | Path to the configuration YAML file |
| `--output` | `-o` | No | `compliance-report.md` | Output path for the Markdown report |
| `--severity-threshold` | `-s` | No | `High` (from config) | Minimum severity to trigger exit code 1 |
| `--version` | `-v` | No | — | Show version and exit |

### Examples

```bash
# Scan all formats in a folder
iac-checker -p ./infra

# Scan only Terraform files
iac-checker -p ./infra -f terraform

# Scan ARM + Bicep only, with Medium threshold
iac-checker -p ./infra -f arm bicep -s Medium

# Generate report to a specific file
iac-checker -p ./infra -o reports/compliance-2024-01-15.md

# Use a project-specific config
iac-checker -p ./infra -c configs/strict.yaml
```

---

## Configuration

The tool reads a YAML configuration file (default: `.iac-checker.yaml`).
If no config file is found, built-in defaults are used.

### Minimal Configuration

```yaml
# Just override what you need — everything else uses defaults
scan:
  severity_threshold: "High"
  exclude_paths:
    - ".terraform/"

tags:
  functional:
    mandatory:
      - app
      - env
  ownership:
    mandatory:
      - owner
```

### Full Configuration Reference

```yaml
# === Rule Overrides ===
# Override severity, enable/disable individual rules
rules:
  WAF-SEC-007:
    enabled: true
    severity: Medium        # Override default severity
  WAF-SVC-002:
    enabled: false          # Disable this rule entirely
  CAF-NAME-001:
    enabled: true
    pattern: "^(rg|vm|st|kv|aks)-[a-z0-9]+-[a-z]+-[a-z0-9]+$"

# === WAF Pillar Settings ===
waf:
  pillars:
    - reliability
    - security
    - cost_optimization
    - operational_excellence
    - performance_efficiency
  service_guides:
    enabled: true
    services:               # Empty list = check all services
      - aks
      - storage
      - key_vault

# === CAF Tagging — 5 Foundational Categories ===
tags:
  functional:
    mandatory: [app, env, tier]
    allowed_environments: [dev, staging, test, qa, prod]
  classification:
    mandatory: [confidentiality, criticality]
  accounting:
    mandatory: [costCenter, department]
  ownership:
    mandatory: [owner, businessUnit]
  iac:
    mandatory: [createdBy]

# === CAF Naming Convention ===
naming:
  convention: "{abbreviation}-{workload}-{env}-{region}-{instance}"
  abbreviations_source: "microsoft"
  delimiter: "-"
  enforce_lowercase: true

# === CAF Governance Policy Categories ===
governance:
  enforce_categories: [RC, SC, OP, CM, DG, RM, AI]

# === AVM Compatibility ===
avm:
  check_avm_alternatives: true
  preferred_source: "Azure/avm-"

# === Scan Settings ===
scan:
  exclude_paths:
    - ".terraform/"
    - "examples/"
    - "tests/"
  severity_threshold: "High"    # Critical | High | Medium | Low
  environment_detection: "tag"
  production_strict_mode: true
```

---

## Examples by Format

The tool applies the **same set of rules** across all three formats. Below are concise examples showing compliant and non-compliant patterns in each format.

> Full working examples are available in the `examples/compliant/` and `examples/non-compliant/` directories.

### Terraform Example

**Compliant** — `examples/compliant/main.tf`

```hcl
resource "azurerm_resource_group" "main" {
  name     = "rg-myapp-prod-eastus2-001"
  location = "eastus2"

  tags = {
    app        = "myapp"
    env        = "prod"
    costCenter = "CC-1234"
    owner      = "team-platform"
  }
}

resource "azurerm_storage_account" "main" {
  name                            = "stmyappprodeastus2001"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  min_tls_version                 = "TLS1_2"
  enable_https_traffic_only       = true
  allow_nested_items_to_be_public = false

  network_rules {
    default_action = "Deny"
  }

  tags = {
    app        = "myapp"
    env        = "prod"
    costCenter = "CC-1234"
    owner      = "team-platform"
  }
}
```

**Non-compliant** — `examples/non-compliant/main.tf`

```hcl
# Missing tags, no CAF naming, hardcoded secret
resource "azurerm_resource_group" "bad" {
  name     = "my-resource-group"    # VIOLATION: no CAF prefix
  location = "eastus2"
  # No tags!                        # VIOLATION: missing mandatory tags
}

resource "azurerm_mssql_server" "bad" {
  name                         = "sql-myapp-prod-eastus2-001"
  resource_group_name          = azurerm_resource_group.bad.name
  location                     = azurerm_resource_group.bad.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd123!"   # CRITICAL: hardcoded secret!

  tags = { env = "production" }   # VIOLATION: invalid env value
}
```

### ARM Template Example

**Compliant** — `examples/compliant/main.json`

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Resources/resourceGroups",
      "apiVersion": "2021-04-01",
      "name": "rg-myapp-prod-eastus2-001",
      "location": "eastus2",
      "tags": {
        "app": "myapp",
        "env": "prod",
        "costCenter": "CC-1234",
        "owner": "team-platform"
      }
    },
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "stmyappprodeastus2001",
      "location": "eastus2",
      "kind": "StorageV2",
      "sku": { "name": "Standard_GRS" },
      "properties": {
        "minimumTlsVersion": "TLS1_2",
        "supportsHttpsTrafficOnly": true,
        "allowBlobPublicAccess": false,
        "networkAcls": { "defaultAction": "Deny" }
      },
      "tags": {
        "app": "myapp",
        "env": "prod",
        "costCenter": "CC-1234",
        "owner": "team-platform"
      }
    }
  ]
}
```

**Non-compliant** — `examples/non-compliant/main.json`

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "mybadstorage",
      "location": "eastus2",
      "kind": "StorageV2",
      "sku": { "name": "Standard_LRS" },
      "properties": {},
      "metadata": {
        "waf-ignore": "WAF-SEC-017"
      }
    }
  ]
}
```

> **Note:** ARM templates use `metadata.waf-ignore` for suppression instead of inline comments.

### Bicep Example

**Compliant** — `examples/compliant/main.bicep`

```bicep
resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: 'rg-myapp-prod-eastus2-001'
  location: 'eastus2'
  tags: {
    app: 'myapp'
    env: 'prod'
    costCenter: 'CC-1234'
    owner: 'team-platform'
  }
}

resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'stmyappprodeastus2001'
  location: 'eastus2'
  kind: 'StorageV2'
  sku: { name: 'Standard_GRS' }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    networkAcls: { defaultAction: 'Deny' }
  }
  tags: {
    app: 'myapp'
    env: 'prod'
    costCenter: 'CC-1234'
    owner: 'team-platform'
  }
}
```

**Non-compliant** — `examples/non-compliant/main.bicep`

```bicep
// waf-ignore: WAF-SEC-017
resource badStorage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mybadstorage'
  location: 'eastus2'
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {}
  // No tags, no TLS, no network rules
}
```

### Console Output

```
$ iac-checker --path ./examples/non-compliant

Found 1 terraform files in ./examples/non-compliant
Found 1 arm files in ./examples/non-compliant
Found 1 bicep files in ./examples/non-compliant
Indexed 24 resources, 0 data sources, 0 modules (from 3 files)
Evaluated 80 rules, found 44 issues
Report written to compliance-report.md
FAIL: 1 Critical, 28 High violations found (threshold: High)
```

---

## Inline Suppressions

Suppress specific rules on individual resources using format-appropriate syntax.

### Terraform (HCL comments)

```hcl
# waf-ignore: WAF-SEC-019
resource "azurerm_mssql_server" "legacy" {
  administrator_login_password = "legacy-password"
}

# caf-ignore: CAF-TAG-012, CAF-NAME-001
resource "azurerm_resource_group" "temp" {
  name     = "temp-rg"
  location = "eastus2"
}
```

### Bicep (line comments)

```bicep
// waf-ignore: WAF-SEC-017
resource badStorage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mybadstorage'
  location: 'eastus2'
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {}
}
```

### ARM Templates (metadata block)

```json
{
  "type": "Microsoft.Storage/storageAccounts",
  "apiVersion": "2023-01-01",
  "name": "mybadstorage",
  "metadata": {
    "waf-ignore": "WAF-SEC-017",
    "caf-ignore": "CAF-TAG-012, CAF-NAME-001"
  }
}
```

| Format | Syntax | Placement |
|--------|--------|-----------|
| Terraform | `# waf-ignore: RULE-ID` | Comment above resource block |
| Bicep | `// waf-ignore: RULE-ID` | Comment above resource block |
| ARM JSON | `"metadata": { "waf-ignore": "RULE-ID" }` | Inside the resource object |

Suppressed findings appear in the report under "Skipped/Suppressed" and **do not** affect the exit code.

---

## Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| `0` | **PASS** — No violations at or above the severity threshold |
| `1` | **FAIL** — One or more violations at or above the severity threshold |

The severity threshold determines which findings trigger a non-zero exit code:

| Threshold | Fails on |
|-----------|----------|
| `Critical` | Critical only |
| `High` | Critical + High |
| `Medium` | Critical + High + Medium |
| `Low` | All findings |

### CI/CD Integration

```yaml
# Azure DevOps Pipeline
- script: |
    pip install iac-checker
    iac-checker --path $(Build.SourcesDirectory)/infra --severity-threshold High
  displayName: 'IaC Compliance Check'
  continueOnError: false

# GitHub Actions
- name: IaC Compliance Check
  run: |
    pip install iac-checker
    iac-checker --path ./infra -s High -o compliance-report.md

- name: Upload Report
  uses: actions/upload-artifact@v4
  with:
    name: compliance-report
    path: compliance-report.md
```

---

## Common Errors & Troubleshooting

### 1. `No IaC files found in <path>`

**Cause:** The `--path` argument points to a directory with no IaC files (`.tf`, `.json` ARM, `.bicep`), or all files are excluded.

```
$ iac-checker --path ./empty-folder
No IaC files found in ./empty-folder
```

**Fix:**
- Verify the path contains `.tf`, `.json` (ARM), or `.bicep` files
- Check your config's `exclude_paths` — you may be excluding the target directory

```bash
# List IaC files manually
find ./infra -name "*.tf" -o -name "*.json" -o -name "*.bicep" -type f
```

---

### 2. `FileNotFoundError: No such file or directory`

**Cause:** The `--path` argument points to a directory that doesn't exist.

```
$ iac-checker --path ./nonexistent
FileNotFoundError: [Errno 2] No such file or directory: './nonexistent'
```

**Fix:** Provide a valid path to an existing directory.

---

### 3. `Error parsing HCL file: <filename>`

**Cause:** A `.tf` file contains invalid HCL syntax that `python-hcl2` cannot parse.

```
Error parsing example/broken.tf: Unexpected token 'xyz' at line 12
Skipping file: example/broken.tf
```

**Fix:**
- Run `terraform fmt` and `terraform validate` on your Terraform files first
- Fix any HCL syntax errors before running the checker
- The tool will skip unparseable files and continue with the rest

---

### 4. `yaml.scanner.ScannerError` — Invalid config YAML

**Cause:** The configuration YAML file has a syntax error.

```
yaml.scanner.ScannerError: while scanning a simple key
  in ".iac-checker.yaml", line 15, column 1
```

**Fix:**
- Validate your YAML with a linter: https://www.yamllint.com/
- Check indentation — YAML requires consistent spaces (no tabs)
- Ensure colons have a space after them: `key: value` (not `key:value`)

---

### 5. `ModuleNotFoundError: No module named 'hcl2'`

**Cause:** The `python-hcl2` dependency is not installed.

```
ModuleNotFoundError: No module named 'hcl2'
```

**Fix:**

```bash
pip install python-hcl2
# or reinstall all dependencies
pip install -e .
```

---

### 6. `ValueError: 'Unknown' is not a valid Severity`

**Cause:** Invalid severity value in the config file or CLI argument.

```
$ iac-checker --path ./infra --severity-threshold Unknown
error: argument --severity-threshold: invalid choice: 'Unknown'
```

**Fix:** Use one of the valid severity values: `Critical`, `High`, `Medium`, `Low` (case-sensitive).

---

### 7. Rule is not being evaluated

**Cause:** The rule may be disabled in the config file.

**Fix:** Check your `.iac-checker.yaml`:

```yaml
rules:
  WAF-SVC-002:
    enabled: false    # <-- This disables the rule!
```

Set `enabled: true` or remove the override entirely to use the default (enabled).

---

### 8. Too many false positives on naming rules

**Cause:** The default naming convention may not match your organization's standard.

**Fix:** Customize the naming settings in your config:

```yaml
naming:
  convention: "{abbreviation}-{workload}-{env}-{region}-{instance}"
  delimiter: "-"
  enforce_lowercase: true

# Or disable naming rules for specific resource types
rules:
  CAF-NAME-001:
    enabled: false
```

---

### 9. Tags check fails even though tags are set via `default_tags`

**Cause:** The tool checks `tags` blocks on individual resources. If you use the `azurerm` provider's `default_tags` feature, the tags won't appear in the HCL resource blocks.

**Fix:** This is a known limitation of static analysis. Options:
1. Add `tags = {}` blocks to resources (they merge with `default_tags` at plan time)
2. Suppress the tagging rules on affected resources:
   ```hcl
   # caf-ignore: CAF-TAG-012
   resource "azurerm_resource_group" "main" { ... }
   ```
3. Disable mandatory tag checks in config if you rely entirely on `default_tags`

---

### 10. `FAIL` exit code in CI but all findings are Low severity

**Cause:** The severity threshold may be set too low.

**Fix:** Set an appropriate threshold in your config or CLI:

```bash
# Only fail on Critical and High
iac-checker --path ./infra --severity-threshold High
```

Or in the config:

```yaml
scan:
  severity_threshold: "High"
```
