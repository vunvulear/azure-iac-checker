"""CAF Networking rules — programmatic checks for network topology and segmentation."""

from typing import Optional

from iac_checker.models.enums import Severity
from iac_checker.models.finding import Finding
from iac_checker.models.resource import TerraformResource
from iac_checker.parser.resource_index import ResourceIndex
from iac_checker.rules.base_rule import BaseRule


class SubnetNsgRule(BaseRule):
    """CAF-NET-003: Each subnet has an associated NSG."""

    rule_id = "CAF-NET-003"
    description = "Each subnet has an associated NSG — no subnets without NSG association"
    severity = Severity.HIGH
    caf_ref = "Segmentation"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-landing-zone-network-segmentation"
    recommendation = (
        "Associate an NSG with every subnet using azurerm_subnet_network_security_group_association. "
        "Exception: GatewaySubnet, AzureFirewallSubnet, AzureBastionSubnet."
    )
    resource_types = {"azurerm_subnet"}

    EXEMPT_SUBNETS = {"GatewaySubnet", "AzureFirewallSubnet", "AzureBastionSubnet", "AzureFirewallManagementSubnet"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        subnet_name = resource.get_attribute("name", "")
        if subnet_name in self.EXEMPT_SUBNETS:
            return self._make_finding(resource, passed=True)

        # Check if there's an NSG association for this subnet
        subnet_ref = f"{resource.resource_type}.{resource.name}"
        has_nsg = any(
            assoc for assoc in index.get_resources_by_type("azurerm_subnet_network_security_group_association")
            if subnet_ref in str(assoc.attributes)
        )

        # Also check if NSG is set directly on the subnet (deprecated but still used)
        has_inline_nsg = resource.has_attribute("network_security_group_id")

        return self._make_finding(resource, passed=(has_nsg or has_inline_nsg))


class NsgWildcardRule(BaseRule):
    """CAF-NET-004: NSG rules follow least-privilege — no wildcard rules."""

    rule_id = "CAF-NET-004"
    description = "NSG rules follow least-privilege — no * source/destination/port rules in production"
    severity = Severity.HIGH
    caf_ref = "Segmentation"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-landing-zone-network-segmentation"
    recommendation = (
        "Replace wildcard (*) source, destination, and port ranges with specific "
        "CIDR blocks, service tags, or port numbers."
    )
    resource_types = {"azurerm_network_security_rule"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        access = resource.get_attribute("access", "")
        if str(access).lower() == "deny":
            return self._make_finding(resource, passed=True)

        # Check for wildcards in Allow rules
        source = str(resource.get_attribute("source_address_prefix", ""))
        dest = str(resource.get_attribute("destination_address_prefix", ""))
        source_port = str(resource.get_attribute("source_port_range", ""))
        dest_port = str(resource.get_attribute("destination_port_range", ""))

        has_wildcard = (
            source == "*" or dest == "*" or
            (dest_port == "*" and source_port == "*")
        )

        if has_wildcard:
            return self._make_finding(
                resource, passed=False,
                description=f"NSG Allow rule uses wildcard (*) — source='{source}', dest='{dest}', ports='{source_port}/{dest_port}'"
            )
        return self._make_finding(resource, passed=True)


class PrivateEndpointDnsRule(BaseRule):
    """CAF-NET-009: Private DNS zone groups for private endpoints."""

    rule_id = "CAF-NET-009"
    description = "Private DNS zone groups configured for private endpoints"
    severity = Severity.MEDIUM
    caf_ref = "DNS"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/network-topology-and-connectivity"
    recommendation = (
        "Configure private_dns_zone_group on private endpoints for automatic DNS registration."
    )
    resource_types = {"azurerm_private_endpoint"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        has_dns_group = resource.has_attribute("private_dns_zone_group")
        return self._make_finding(resource, passed=has_dns_group)


class VnetPeeringRule(BaseRule):
    """CAF-NET-001: Hub-spoke topology — VNet peering configured."""

    rule_id = "CAF-NET-001"
    description = "Hub-spoke network topology — VNet peering configured for connectivity"
    severity = Severity.MEDIUM
    caf_ref = "Connectivity"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/network-topology-and-connectivity"
    recommendation = (
        "Use azurerm_virtual_network_peering to connect spoke VNets to a central hub "
        "for shared services and centralized network management."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        vnets = index.get_resources_by_type("azurerm_virtual_network")
        peerings = index.get_resources_by_type("azurerm_virtual_network_peering")
        # If there are 2+ VNets, peering should exist
        needs_peering = len(vnets) > 1
        has_peering = len(peerings) > 0
        passed = has_peering if needs_peering else True
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="networking",
            resource_name="vnet_peering",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            caf_ref=self.caf_ref,
            passed=passed,
        )


class AzureFirewallRule(BaseRule):
    """CAF-NET-002: Azure Firewall or NVA deployed in hub network."""

    rule_id = "CAF-NET-002"
    description = "Azure Firewall or network virtual appliance deployed in hub network"
    severity = Severity.HIGH
    caf_ref = "Connectivity"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/network-topology-and-connectivity"
    recommendation = (
        "Deploy azurerm_firewall in the hub virtual network for centralized "
        "network traffic inspection and east-west/north-south filtering."
    )
    resource_types = set()
    applies_to_all = False

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        return None

    def evaluate_global(self, index: ResourceIndex) -> Optional[Finding]:
        has_firewall = bool(
            index.get_resources_by_type("azurerm_firewall")
            or index.get_resources_by_type("azurerm_firewall_policy")
        )
        return Finding(
            rule_id=self.rule_id,
            description=self.description,
            severity=self.severity,
            file_path="global",
            line_number=0,
            resource_type="networking",
            resource_name="azure_firewall",
            recommendation=self.recommendation,
            doc_url=self.doc_url,
            caf_ref=self.caf_ref,
            passed=has_firewall,
        )


class VnetDnsConfigRule(BaseRule):
    """CAF-NET-010: VNet DNS servers configured."""

    rule_id = "CAF-NET-010"
    description = "Virtual network DNS servers explicitly configured for name resolution"
    severity = Severity.LOW
    caf_ref = "DNS"
    doc_url = "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/network-topology-and-connectivity"
    recommendation = (
        "Set dns_servers on azurerm_virtual_network to point to custom DNS servers "
        "or Azure Private DNS Resolver for hybrid name resolution."
    )
    resource_types = {"azurerm_virtual_network"}

    def evaluate(self, resource: TerraformResource, index: ResourceIndex) -> Optional[Finding]:
        if not self.applies_to(resource):
            return None

        dns_servers = resource.get_attribute("dns_servers")
        has_dns = isinstance(dns_servers, list) and len(dns_servers) > 0
        return self._make_finding(resource, passed=has_dns)


RULES = [
    SubnetNsgRule(),
    NsgWildcardRule(),
    PrivateEndpointDnsRule(),
    VnetPeeringRule(),
    AzureFirewallRule(),
    VnetDnsConfigRule(),
]
