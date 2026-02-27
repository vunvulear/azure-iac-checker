// Non-compliant Bicep example — mirrors the non-compliant Terraform and ARM examples.
// Each resource has intentional violations of WAF and CAF best practices.

targetScope = 'subscription'

// VIOLATION: Resource group with wrong naming and no tags
resource rg 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: 'my-resource-group'
  location: 'eastus2'
}

// VIOLATION: Storage with LRS (no geo-redundancy), no TLS, no network rules, no tags
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mybadstorage'
  location: 'eastus2'
  sku: {
    name: 'Premium_LRS'
  }
  kind: 'StorageV2'
  properties: {}
}

// VIOLATION: SQL Server with hardcoded password and invalid env tag value
resource sqlServer 'Microsoft.Sql/servers@2023-05-01' = {
  name: 'sql-myapp-prod-eastus2-001'
  location: 'eastus2'
  tags: {
    env: 'production'
  }
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: 'P@ssw0rd123!'
  }
}

// VIOLATION: Key Vault without RBAC or purge protection
resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: 'kv-myapp-prod-eus2-002'
  location: 'eastus2'
  tags: {
    app: 'myapp'
    env: 'prod'
    costCenter: 'CC-1234'
    owner: 'team-platform'
  }
  properties: {
    tenantId: '00000000-0000-0000-0000-000000000000'
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: false
    enablePurgeProtection: false
  }
}

// VIOLATION: AKS without zones, private cluster, or managed identity
resource aks 'Microsoft.ContainerService/managedClusters@2023-08-01' = {
  name: 'aks-myapp-prod-eastus2-001'
  location: 'eastus2'
  tags: {
    app: 'myapp'
    env: 'prod'
    costCenter: 'CC-1234'
    owner: 'team-platform'
  }
  properties: {
    dnsPrefix: 'myaks'
    agentPoolProfiles: [
      {
        name: 'default'
        count: 1
        vmSize: 'Standard_D2_v2'
        mode: 'System'
      }
    ]
  }
}

// VIOLATION: VM without availability zone
resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: 'vm-myapp-prod-eastus2-001'
  location: 'eastus2'
  tags: {
    app: 'myapp'
    env: 'prod'
    costCenter: 'CC-1234'
    owner: 'team-platform'
  }
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
    osProfile: {
      computerName: 'vm-myapp'
      adminUsername: 'azureuser'
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/azureuser/.ssh/authorized_keys'
              keyData: 'ssh-rsa AAAA...'
            }
          ]
        }
      }
    }
    storageProfile: {
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
      }
    }
  }
}

// VIOLATION: NSG rule with wildcard source/destination
resource nsgRule 'Microsoft.Network/networkSecurityGroups/securityRules@2023-05-01' = {
  name: 'nsg-myapp-prod/allow-all-inbound'
  properties: {
    priority: 100
    direction: 'Inbound'
    access: 'Allow'
    protocol: '*'
    sourcePortRange: '*'
    destinationPortRange: '*'
    sourceAddressPrefix: '*'
    destinationAddressPrefix: '*'
  }
}

// Example of inline suppression in Bicep
// waf-ignore: WAF-SEC-019
resource sqlLegacy 'Microsoft.Sql/servers@2023-05-01' = {
  name: 'sql-legacy-prod-eastus2-001'
  location: 'eastus2'
  tags: {
    app: 'legacy'
    env: 'prod'
    costCenter: 'CC-0000'
    owner: 'team-legacy'
  }
  properties: {
    administratorLogin: 'legacyadmin'
    administratorLoginPassword: 'LegacyP@ss!'
  }
}
