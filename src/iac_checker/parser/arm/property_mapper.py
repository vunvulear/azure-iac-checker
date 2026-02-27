"""ARM property name → Terraform attribute name mapping and flattening."""

import re
from typing import Any, Dict


# Per-resource-type property mapping: ARM JSON path → Terraform attribute name
# Keys are lowercase ARM resource types.
_PROPERTY_MAP: Dict[str, Dict[str, str]] = {
    "microsoft.storage/storageaccounts": {
        "properties.minimumTlsVersion": "min_tls_version",
        "properties.supportsHttpsTrafficOnly": "enable_https_traffic_only",
        "properties.allowBlobPublicAccess": "allow_nested_items_to_be_public",
        "properties.networkAcls.defaultAction": "network_rules.default_action",
        "properties.networkAcls.bypass": "network_rules.bypass",
        "properties.encryption.requireInfrastructureEncryption": "infrastructure_encryption_enabled",
        "properties.publicNetworkAccess": "public_network_access_enabled",
        "properties.encryption.services.blob.enabled": "blob_encryption_enabled",
        "sku.name": "account_replication_type",
        "kind": "account_kind",
        "properties.accessTier": "access_tier",
    },
    "microsoft.keyvault/vaults": {
        "properties.enableRbacAuthorization": "enable_rbac_authorization",
        "properties.enablePurgeProtection": "purge_protection_enabled",
        "properties.enableSoftDelete": "soft_delete_enabled",
        "properties.softDeleteRetentionInDays": "soft_delete_retention_days",
        "properties.networkAcls.defaultAction": "network_acls.default_action",
        "properties.tenantId": "tenant_id",
        "properties.sku.name": "sku_name",
    },
    "microsoft.keyvault/vaults/keys": {
        "properties.attributes.exp": "expiration_date",
        "properties.attributes.nbf": "not_before_date",
        "properties.kty": "key_type",
        "properties.keySize": "key_size",
    },
    "microsoft.web/sites": {
        "properties.httpsOnly": "https_only",
        "properties.siteConfig.minTlsVersion": "min_tls_version",
        "properties.siteConfig.ftpsState": "ftps_state",
        "properties.siteConfig.http20Enabled": "http2_enabled",
        "properties.clientAffinityEnabled": "client_affinity_enabled",
        "identity.type": "identity.type",
    },
    "microsoft.web/serverfarms": {
        "sku.name": "sku_name",
        "sku.tier": "sku_tier",
        "sku.size": "size",
        "sku.capacity": "worker_count",
        "properties.reserved": "os_type",
    },
    "microsoft.sql/servers": {
        "properties.publicNetworkAccess": "public_network_access_enabled",
        "properties.minimalTlsVersion": "minimum_tls_version",
        "properties.administratorLogin": "administrator_login",
    },
    "microsoft.sql/servers/databases": {
        "properties.collation": "collation",
        "properties.maxSizeBytes": "max_size_gb",
        "sku.name": "sku_name",
        "properties.zoneRedundant": "zone_redundant",
        "properties.readScale": "read_scale",
        "properties.longTermRetentionPolicy": "long_term_retention_policy",
        "properties.shortTermRetentionPolicy": "short_term_retention_policy",
    },
    "microsoft.containerservice/managedclusters": {
        "properties.apiServerAccessProfile.enablePrivateCluster": "private_cluster_enabled",
        "properties.networkProfile.networkPlugin": "network_profile.network_plugin",
        "properties.networkProfile.networkPolicy": "network_profile.network_policy",
        "properties.addonProfiles": "addon_profile",
        "identity.type": "identity.type",
        "sku.tier": "sku_tier",
    },
    "microsoft.network/virtualnetworks": {
        "properties.addressSpace.addressPrefixes": "address_space",
        "properties.dhcpOptions.dnsServers": "dns_servers",
        "properties.enableDdosProtection": "ddos_protection_plan_enabled",
        "properties.subnets": "subnet",
    },
    "microsoft.network/virtualnetworks/subnets": {
        "properties.addressPrefix": "address_prefixes",
        "properties.networkSecurityGroup.id": "network_security_group_id",
        "properties.serviceEndpoints": "service_endpoints",
        "properties.delegations": "delegation",
    },
    "microsoft.network/networksecuritygroups/securityrules": {
        "properties.access": "access",
        "properties.direction": "direction",
        "properties.priority": "priority",
        "properties.protocol": "protocol",
        "properties.sourceAddressPrefix": "source_address_prefix",
        "properties.destinationAddressPrefix": "destination_address_prefix",
        "properties.sourcePortRange": "source_port_range",
        "properties.destinationPortRange": "destination_port_range",
    },
    "microsoft.network/publicipaddresses": {
        "sku.name": "sku",
        "properties.publicIPAllocationMethod": "allocation_method",
        "zones": "zones",
    },
    "microsoft.compute/virtualmachines": {
        "properties.hardwareProfile.vmSize": "size",
        "zones": "zone",
        "identity.type": "identity.type",
        "properties.osProfile.adminUsername": "admin_username",
        "properties.storageProfile.osDisk.managedDisk.storageAccountType": "os_disk.storage_account_type",
    },
    "microsoft.compute/disks": {
        "sku.name": "storage_account_type",
        "properties.diskSizeGB": "disk_size_gb",
        "zones": "zone",
    },
    "microsoft.network/firewalls": {
        "sku.tier": "sku_tier",
        "sku.name": "sku_name",
        "properties.threatIntelMode": "threat_intel_mode",
    },
    "microsoft.servicebus/namespaces": {
        "sku.name": "sku",
        "properties.disableLocalAuth": "local_auth_enabled",
        "properties.minimumTlsVersion": "minimum_tls_version",
    },
    "microsoft.eventhub/namespaces": {
        "sku.name": "sku",
        "properties.disableLocalAuth": "local_auth_enabled",
        "properties.minimumTlsVersion": "minimum_tls_version",
    },
    "microsoft.insights/diagnosticsettings": {
        "properties.workspaceId": "log_analytics_workspace_id",
        "properties.storageAccountId": "storage_account_id",
    },
    "microsoft.insights/metricalerts": {
        "properties.severity": "severity",
        "properties.enabled": "enabled",
        "properties.scopes": "scopes",
    },
    "microsoft.insights/autoscalesettings": {
        "properties.profiles.0": "profile",
        "properties.enabled": "enabled",
        "properties.targetResourceUri": "target_resource_id",
    },
    "microsoft.authorization/locks": {
        "properties.level": "lock_level",
        "properties.notes": "notes",
    },
    "microsoft.cache/redis": {
        "properties.sku.name": "sku_name",
        "properties.sku.family": "family",
        "properties.sku.capacity": "capacity",
        "properties.enableNonSslPort": "enable_non_ssl_port",
        "properties.minimumTlsVersion": "minimum_tls_version",
    },
    "microsoft.cdn/profiles": {
        "sku.name": "sku",
    },
    "microsoft.operationalinsights/workspaces": {
        "properties.sku.name": "sku",
        "properties.retentionInDays": "retention_in_days",
    },
    "microsoft.cognitiveservices/accounts": {
        "properties.disableLocalAuth": "local_auth_enabled",
        "properties.publicNetworkAccess": "public_network_access_enabled",
        "sku.name": "sku_name",
        "kind": "kind",
    },
    "microsoft.network/privateendpoints": {
        "properties.privateLinkServiceConnections": "private_service_connection",
        "properties.customDnsConfigs": "private_dns_zone_group",
    },
}


# ARM properties where the boolean value must be inverted when mapping to Terraform.
# ARM "disableLocalAuth: true" → Terraform "local_auth_enabled: false"
_INVERTED_BOOLEANS: Dict[str, str] = {
    "disable_local_auth": "local_auth_enabled",
}


def flatten_arm_resource(arm_type: str, arm_resource: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten an ARM resource into a Terraform-like flat attribute dict.

    Merges top-level fields (location, tags, sku, kind, zones, identity)
    plus mapped properties into a single dict.
    """
    attrs: Dict[str, Any] = {}

    # Direct top-level fields
    for key in ("location", "tags", "zones", "identity", "sku", "kind"):
        if key in arm_resource:
            attrs[key] = arm_resource[key]

    # Apply resource-type-specific property mapping
    normalized_type = arm_type.lower()
    prop_map = _PROPERTY_MAP.get(normalized_type, {})

    for arm_path, tf_attr in prop_map.items():
        value = _resolve_path(arm_resource, arm_path)
        if value is not None:
            _set_nested(attrs, tf_attr, value)

    # Fallback: also copy all properties.* that weren't explicitly mapped
    properties = arm_resource.get("properties", {})
    if isinstance(properties, dict):
        for key, value in properties.items():
            # camelCase → snake_case conversion
            snake = _camel_to_snake(key)
            if snake not in attrs:
                attrs[snake] = value

    # Post-process: invert boolean values for ARM→Terraform semantic differences
    for arm_attr, tf_attr in _INVERTED_BOOLEANS.items():
        if arm_attr in attrs:
            val = attrs.pop(arm_attr)
            if isinstance(val, bool):
                attrs[tf_attr] = not val
            else:
                attrs[tf_attr] = val

    return attrs


def _resolve_path(obj: Any, path: str) -> Any:
    """Resolve a dotted path like 'properties.networkAcls.defaultAction' from a nested dict."""
    parts = path.split(".")
    current = obj
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and current:
            # Handle array-indexed paths like [0]
            try:
                idx = int(part.strip("[]"))
                current = current[idx]
            except (ValueError, IndexError):
                current = current[0].get(part) if isinstance(current[0], dict) else None
        else:
            return None
        if current is None:
            return None
    return current


def _set_nested(d: Dict[str, Any], path: str, value: Any) -> None:
    """Set a dotted path in a dict, creating intermediate dicts as needed."""
    parts = path.split(".")
    for part in parts[:-1]:
        d = d.setdefault(part, {})
    d[parts[-1]] = value


def _camel_to_snake(name: str) -> str:
    """Convert camelCase to snake_case."""
    s = re.sub(r"([A-Z])", r"_\1", name).lower().lstrip("_")
    return s
