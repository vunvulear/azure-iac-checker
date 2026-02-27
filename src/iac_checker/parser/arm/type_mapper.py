"""ARM ↔ Terraform resource type bidirectional mapping."""

# ARM resource type → Terraform azurerm_* resource type
ARM_TO_TERRAFORM = {
    # Compute
    "microsoft.compute/virtualmachines": "azurerm_linux_virtual_machine",
    "microsoft.compute/virtualmachinescalesets": "azurerm_orchestrated_virtual_machine_scale_set",
    "microsoft.compute/disks": "azurerm_managed_disk",
    "microsoft.compute/availabilitysets": "azurerm_availability_set",
    "microsoft.compute/images": "azurerm_image",

    # Containers
    "microsoft.containerservice/managedclusters": "azurerm_kubernetes_cluster",
    "microsoft.containerregistry/registries": "azurerm_container_registry",
    "microsoft.containerinstance/containergroups": "azurerm_container_group",

    # Networking
    "microsoft.network/virtualnetworks": "azurerm_virtual_network",
    "microsoft.network/virtualnetworks/subnets": "azurerm_subnet",
    "microsoft.network/networksecuritygroups": "azurerm_network_security_group",
    "microsoft.network/networksecuritygroups/securityrules": "azurerm_network_security_rule",
    "microsoft.network/publicipaddresses": "azurerm_public_ip",
    "microsoft.network/loadbalancers": "azurerm_lb",
    "microsoft.network/applicationgateways": "azurerm_application_gateway",
    "microsoft.network/privatednszones": "azurerm_private_dns_zone",
    "microsoft.network/privateendpoints": "azurerm_private_endpoint",
    "microsoft.network/firewalls": "azurerm_firewall",
    "microsoft.network/firewallpolicies": "azurerm_firewall_policy",
    "microsoft.network/ddosprotectionplans": "azurerm_network_ddos_protection_plan",
    "microsoft.network/networkinterfaces": "azurerm_network_interface",
    "microsoft.network/routetables": "azurerm_route_table",
    "microsoft.network/virtualnetworkgateways": "azurerm_virtual_network_gateway",
    "microsoft.network/virtualnetworkpeerings": "azurerm_virtual_network_peering",
    "microsoft.network/bastionhosts": "azurerm_bastion_host",
    "microsoft.network/frontdoors": "azurerm_frontdoor",
    "microsoft.network/natgateways": "azurerm_nat_gateway",
    "microsoft.network/trafficmanagerprofiles": "azurerm_traffic_manager_profile",

    # Storage
    "microsoft.storage/storageaccounts": "azurerm_storage_account",
    "microsoft.storage/storageaccounts/blobservices/containers": "azurerm_storage_container",

    # Databases
    "microsoft.sql/servers": "azurerm_mssql_server",
    "microsoft.sql/servers/databases": "azurerm_mssql_database",
    "microsoft.dbformysql/flexibleservers": "azurerm_mysql_flexible_server",
    "microsoft.dbforpostgresql/flexibleservers": "azurerm_postgresql_flexible_server",
    "microsoft.documentdb/databaseaccounts": "azurerm_cosmosdb_account",

    # Key Vault
    "microsoft.keyvault/vaults": "azurerm_key_vault",
    "microsoft.keyvault/vaults/keys": "azurerm_key_vault_key",
    "microsoft.keyvault/vaults/secrets": "azurerm_key_vault_secret",

    # Web / App Service
    "microsoft.web/serverfarms": "azurerm_service_plan",
    "microsoft.web/sites": "azurerm_linux_web_app",
    "microsoft.web/sites/slots": "azurerm_linux_web_app_slot",
    "microsoft.web/certificates": "azurerm_app_service_certificate",

    # Monitoring
    "microsoft.insights/diagnosticsettings": "azurerm_monitor_diagnostic_setting",
    "microsoft.insights/metricalerts": "azurerm_monitor_metric_alert",
    "microsoft.insights/activitylogalerts": "azurerm_monitor_activity_log_alert",
    "microsoft.insights/autoscalesettings": "azurerm_monitor_autoscale_setting",
    "microsoft.insights/scheduledqueryrules": "azurerm_monitor_scheduled_query_rules_alert",
    "microsoft.insights/components": "azurerm_application_insights",
    "microsoft.operationalinsights/workspaces": "azurerm_log_analytics_workspace",

    # Security
    "microsoft.security/pricings": "azurerm_security_center_subscription_pricing",
    "microsoft.security/securitycontacts": "azurerm_security_center_contact",

    # Governance
    "microsoft.authorization/roleassignments": "azurerm_role_assignment",
    "microsoft.authorization/roledefinitions": "azurerm_role_definition",
    "microsoft.authorization/locks": "azurerm_management_lock",
    "microsoft.authorization/policydefinitions": "azurerm_policy_definition",
    "microsoft.authorization/policysetdefinitions": "azurerm_policy_set_definition",
    "microsoft.authorization/policyassignments": "azurerm_policy_assignment",

    # Resource management
    "microsoft.resources/resourcegroups": "azurerm_resource_group",

    # Messaging
    "microsoft.servicebus/namespaces": "azurerm_servicebus_namespace",
    "microsoft.eventhub/namespaces": "azurerm_eventhub_namespace",

    # CDN
    "microsoft.cdn/profiles": "azurerm_cdn_profile",
    "microsoft.cdn/profiles/endpoints": "azurerm_cdn_endpoint",
    "microsoft.cdn/profiles/afdendpoints": "azurerm_cdn_frontdoor_endpoint",

    # Cache
    "microsoft.cache/redis": "azurerm_redis_cache",

    # Cognitive Services
    "microsoft.cognitiveservices/accounts": "azurerm_cognitive_account",

    # Search
    "microsoft.search/searchservices": "azurerm_search_service",

    # SignalR
    "microsoft.signalrservice/signalr": "azurerm_signalr_service",

    # Consumption
    "microsoft.consumption/budgets": "azurerm_consumption_budget_resource_group",

    # WAF
    "microsoft.network/frontdoorwebapplicationfirewallpolicies": "azurerm_cdn_frontdoor_firewall_policy",
    "microsoft.network/applicationgatewaywebapplicationfirewallpolicies": "azurerm_web_application_firewall_policy",

    # Functions
    "microsoft.web/sites/functions": "azurerm_function_app",

    # Logic Apps
    "microsoft.logic/workflows": "azurerm_logic_app_workflow",

    # API Management
    "microsoft.apimanagement/service": "azurerm_api_management",

    # Recovery Services
    "microsoft.recoveryservices/vaults": "azurerm_recovery_services_vault",
}

# Reverse mapping: Terraform → ARM
TERRAFORM_TO_ARM = {v: k for k, v in ARM_TO_TERRAFORM.items()}


def arm_type_to_terraform(arm_type: str) -> str:
    """Convert an ARM resource type to a Terraform azurerm_* type.

    Returns the mapped type, or a generated azurerm_* name if not in mapping.
    """
    normalized = arm_type.lower()
    mapped = ARM_TO_TERRAFORM.get(normalized)
    if mapped:
        return mapped
    # Fallback: generate a plausible azurerm_* name
    # e.g. "Microsoft.Foo/bars" → "azurerm_foo_bar"
    parts = normalized.replace("microsoft.", "").split("/")
    return "azurerm_" + "_".join(p.rstrip("s") for p in parts if p)


def terraform_type_to_arm(terraform_type: str) -> str:
    """Convert a Terraform azurerm_* type to an ARM resource type.

    Returns the mapped type, or empty string if not in mapping.
    """
    return TERRAFORM_TO_ARM.get(terraform_type, "")
