"""Resource index — builds a structured index of all IaC resources."""

from typing import Any, Dict, List

from iac_checker.models.resource import TerraformResource
from iac_checker.parser.parsed_file import ParsedFile


class ResourceIndex:
    def __init__(self):
        self.resources: List[TerraformResource] = []
        self.data_sources: List[TerraformResource] = []
        self.modules: List[TerraformResource] = []
        self.variables: List[TerraformResource] = []
        self.outputs: List[TerraformResource] = []
        self.providers: List[TerraformResource] = []
        self.backend: Dict[str, Any] = {}
        self.raw_lines_by_file: Dict[str, List[str]] = {}

    def build(self, parsed_files: List[ParsedFile]) -> None:
        """Build the index from parsed IaC files (Terraform, ARM, Bicep)."""
        for pf in parsed_files:
            self.raw_lines_by_file[str(pf.file_path)] = pf.raw_lines
            self._index_file(pf)

    def _index_file(self, pf: ParsedFile) -> None:
        content = pf.content

        # Resources and data sources use {type: {name: attrs}} blocks
        for resource_block in content.get("resource", []):
            for resource_type, instances in resource_block.items():
                for name, attrs in self._iter_instances(instances):
                    line = pf.find_line_number("resource", resource_type, name)
                    self.resources.append(TerraformResource(
                        resource_type=resource_type, name=name,
                        attributes=attrs, file_path=str(pf.file_path),
                        line_number=line, block_type="resource",
                        source_format=pf.source_format,
                    ))

        for data_block in content.get("data", []):
            for data_type, instances in data_block.items():
                for name, attrs in self._iter_instances(instances):
                    line = pf.find_line_number("data", data_type, name)
                    self.data_sources.append(TerraformResource(
                        resource_type=data_type, name=name,
                        attributes=attrs, file_path=str(pf.file_path),
                        line_number=line, block_type="data",
                        source_format=pf.source_format,
                    ))

        # Modules, variables, outputs use {name: attrs} blocks
        for block_type, target_list in (
            ("module", self.modules),
            ("variable", self.variables),
            ("output", self.outputs),
        ):
            for block in content.get(block_type, []):
                if isinstance(block, dict):
                    for name, attributes in block.items():
                        line = pf.find_line_number(block_type, "", name)
                        target_list.append(TerraformResource(
                            resource_type=block_type, name=name,
                            attributes=attributes if isinstance(attributes, dict) else {},
                            file_path=str(pf.file_path),
                            line_number=line, block_type=block_type,
                            source_format=pf.source_format,
                        ))

        # Terraform backend
        for terraform_block in content.get("terraform", []):
            if isinstance(terraform_block, dict) and "backend" in terraform_block:
                self.backend = terraform_block["backend"]

    @staticmethod
    def _iter_instances(instances: Any) -> List:
        """Normalize python-hcl2 instance formats into a list of (name, attrs) tuples.

        python-hcl2 v7.x returns {name: attrs} dict;
        python-hcl2 v4.x returns [{name: attrs}] list.
        """
        if isinstance(instances, dict):
            return [(k, v if isinstance(v, dict) else {}) for k, v in instances.items()]
        if isinstance(instances, list):
            result = []
            for inst in instances:
                if isinstance(inst, dict):
                    result.extend(
                        (k, v if isinstance(v, dict) else {}) for k, v in inst.items()
                    )
            return result
        return []

    def get_resources_by_type(self, resource_type: str) -> List[TerraformResource]:
        """Get all resources of a specific type."""
        return [r for r in self.resources if r.resource_type == resource_type]

    def get_all_blocks(self) -> List[TerraformResource]:
        """Get all indexed blocks (resources, data, modules, vars, outputs)."""
        return self.resources + self.data_sources + self.modules + self.variables + self.outputs

    def get_inline_suppressions(self, file_path: str, line_number: int) -> List[str]:
        """Check lines above a resource for waf-ignore/caf-ignore comments.

        Supports:
            Terraform:  # waf-ignore: WAF-SEC-019
            Bicep:      // waf-ignore: WAF-SEC-019
            ARM JSON:   handled via _waf_ignore/_caf_ignore resource attributes

        Returns list of suppressed rule IDs.
        """
        lines = self.raw_lines_by_file.get(file_path, [])
        suppressions: List[str] = []
        # Check the 5 lines above the resource definition (0-indexed)
        start = max(0, line_number - 6)
        end = max(0, line_number - 1)
        for i in range(start, end):
            if i >= len(lines):
                continue
            line = lines[i].strip()
            # Terraform: # waf-ignore: / # caf-ignore:
            # Bicep:     // waf-ignore: / // caf-ignore:
            for prefix in ("# waf-ignore:", "# caf-ignore:",
                           "// waf-ignore:", "// caf-ignore:"):
                if prefix in line:
                    _, _, remainder = line.partition(prefix)
                    rule_ids = [r.strip() for r in remainder.split(",") if r.strip()]
                    suppressions.extend(rule_ids)
        return suppressions

    def get_arm_metadata_suppressions(self, resource: "TerraformResource") -> List[str]:
        """Get suppressions from ARM metadata attributes (_waf_ignore, _caf_ignore).

        ARM templates use resource metadata for suppressions:
            "metadata": { "waf-ignore": "WAF-SEC-019, WAF-REL-002" }
        """
        suppressions: List[str] = []
        for attr in ("_waf_ignore", "_caf_ignore"):
            value = resource.attributes.get(attr, "")
            if value:
                rule_ids = [r.strip() for r in str(value).split(",") if r.strip()]
                suppressions.extend(rule_ids)
        return suppressions
