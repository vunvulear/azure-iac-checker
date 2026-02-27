// Compliant Bicep example — mirrors the compliant Terraform and ARM examples.
// All resources follow WAF and CAF best practices.

targetScope = 'subscription'

@description('Primary deployment region')
param location string = 'eastus2'

@description('Azure AD tenant ID for Key Vault')
param tenantId string

var commonTags = {
  app: 'myapp'
  env: 'prod'
  costCenter: 'CC-1234'
  owner: 'team-platform'
  createdBy: 'Bicep'
}

// --- Resource Group ---
resource rg 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: 'rg-myapp-prod-eastus2-001'
  location: location
  tags: commonTags
}

// --- Storage Account: GRS, TLS 1.2, HTTPS-only, no public blob, infra encryption ---
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'stmyappprodeastus2001'
  location: location
  tags: commonTags
  sku: {
    name: 'Standard_GRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
    encryption: {
      requireInfrastructureEncryption: true
      services: {
        blob: { enabled: true }
        file: { enabled: true }
      }
    }
  }
}

// --- Key Vault: RBAC, purge protection, soft delete, network deny ---
resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: 'kv-myapp-prod-eus2-001'
  location: location
  tags: commonTags
  properties: {
    tenantId: tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enablePurgeProtection: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}

// --- Virtual Network with subnets and custom DNS ---
resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: 'vnet-myapp-prod-eastus2-001'
  location: location
  tags: commonTags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    dhcpOptions: {
      dnsServers: [
        '10.0.0.4'
        '10.0.0.5'
      ]
    }
    subnets: [
      {
        name: 'snet-app'
        properties: {
          addressPrefix: '10.0.1.0/24'
        }
      }
      {
        name: 'snet-data'
        properties: {
          addressPrefix: '10.0.2.0/24'
        }
      }
    ]
  }
}

// --- Monitoring: metric alert ---
resource cpuAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'cpu-alert-high'
  location: 'global'
  tags: commonTags
  properties: {
    severity: 2
    enabled: true
    description: 'Alert when CPU exceeds 80%'
    scopes: []
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'HighCPU'
          metricName: 'Percentage CPU'
          operator: 'GreaterThan'
          threshold: 80
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
  }
}

// --- Log Analytics workspace ---
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'law-myapp-prod-eastus2-001'
  location: location
  tags: commonTags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
  }
}

// --- Diagnostic settings: activity log export ---
resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01' = {
  name: 'activity-log-export'
  properties: {
    workspaceId: logAnalytics.id
  }
}

// --- Budget alert ---
resource budget 'Microsoft.Consumption/budgets@2023-03-01' = {
  name: 'monthly-budget-prod'
  properties: {
    category: 'Cost'
    amount: 5000
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: '2025-01-01T00:00:00Z'
    }
  }
}

// --- Outputs ---
output storageAccountId string = storageAccount.id
output keyVaultUri string = keyVault.properties.vaultUri
