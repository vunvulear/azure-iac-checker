"""Secret detector — finds hardcoded secrets in Terraform files via regex patterns."""

import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class SecretMatch:
    file_path: str
    line_number: int
    pattern_name: str
    matched_key: str


# Patterns that indicate a hardcoded secret (attribute name + value patterns)
SECRET_ATTRIBUTE_PATTERNS = [
    re.compile(r'(password|admin_password|administrator_login_password)\s*=\s*"[^"$]', re.IGNORECASE),
    re.compile(r'(secret|client_secret|shared_key)\s*=\s*"[^"$]', re.IGNORECASE),
    re.compile(r'(api_key|apikey|access_key|primary_access_key|secondary_access_key)\s*=\s*"[^"$]', re.IGNORECASE),
    re.compile(r'(connection_string|storage_connection_string)\s*=\s*"[^"$]', re.IGNORECASE),
    re.compile(r'(sas_token|shared_access_key)\s*=\s*"[^"$]', re.IGNORECASE),
    re.compile(r'(private_key|ssh_key|ssl_certificate)\s*=\s*"[^"$]', re.IGNORECASE),
]

# Value patterns that look like secrets regardless of attribute name
SECRET_VALUE_PATTERNS = [
    re.compile(r'=\s*"[A-Za-z0-9+/]{40,}={0,2}"'),  # Base64-encoded strings (40+ chars)
    re.compile(r'=\s*"AccountKey=[^"]+'),  # Azure Storage connection string
    re.compile(r'=\s*"DefaultEndpointsProtocol=https;AccountName=[^"]+'),  # Full connection string
    re.compile(r'=\s*"sv=\d{4}-\d{2}-\d{2}&s[a-z]=[^"]+'),  # SAS token
]


class SecretDetector:
    """Detects hardcoded secrets in Terraform file lines."""

    def scan_lines(self, file_path: str, lines: List[str]) -> List[SecretMatch]:
        """Scan file lines for hardcoded secrets."""
        matches = []

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Check attribute patterns first
            attr_matched = False
            for pattern in SECRET_ATTRIBUTE_PATTERNS:
                key_match = pattern.search(stripped)
                if key_match:
                    matches.append(SecretMatch(
                        file_path=file_path,
                        line_number=line_num,
                        pattern_name="hardcoded_secret_attribute",
                        matched_key=key_match.group(1),
                    ))
                    attr_matched = True
                    break

            # Only check value patterns if no attribute pattern matched (avoid duplicates)
            if not attr_matched:
                for pattern in SECRET_VALUE_PATTERNS:
                    if pattern.search(stripped):
                        matches.append(SecretMatch(
                            file_path=file_path,
                            line_number=line_num,
                            pattern_name="hardcoded_secret_value",
                            matched_key="suspicious_value",
                        ))
                        break

        return matches
