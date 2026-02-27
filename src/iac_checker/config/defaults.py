"""Default configuration values for the compliance checker."""

DEFAULTS = {
    "scan": {
        "exclude_paths": [".terraform/", "examples/", "tests/"],
        "severity_threshold": "High",
        "environment_detection": "tag",
        "production_strict_mode": True,
    },
    "waf": {
        "pillars": [
            "reliability",
            "security",
            "cost_optimization",
            "operational_excellence",
            "performance_efficiency",
        ],
        "service_guides": {
            "enabled": True,
            "services": [],  # empty = all services
        },
    },
    "tags": {
        "functional": {
            "mandatory": ["app", "env"],
        },
        "accounting": {
            "mandatory": ["costCenter"],
        },
        "ownership": {
            "mandatory": ["owner"],
        },
    },
    "naming": {
        "convention": "{abbreviation}-{workload}-{env}-{region}-{instance}",
        "abbreviations_source": "microsoft",
        "delimiter": "-",
        "enforce_lowercase": True,
        "instance_format": "001",
    },
    "governance": {
        "enforce_categories": ["RC", "SC", "OP", "CM", "DG", "RM", "AI"],
    },
    "avm": {
        "check_avm_alternatives": False,
        "preferred_source": "Azure/avm-",
    },
    "rules": {},
}
