"""Tests for the hardcoded secret detector."""

import pytest
from iac_checker.utils.secret_detector import SecretDetector


class TestSecretDetector:
    def setup_method(self):
        self.detector = SecretDetector()

    def test_detect_hardcoded_password(self):
        lines = [
            'resource "azurerm_mssql_server" "main" {',
            '  administrator_login_password = "P@ssw0rd123!"',
            '}',
        ]
        matches = self.detector.scan_lines("main.tf", lines)
        assert len(matches) >= 1
        assert matches[0].line_number == 2
        assert "password" in matches[0].matched_key.lower()

    def test_detect_client_secret(self):
        lines = [
            '  client_secret = "super-secret-value-123"',
        ]
        matches = self.detector.scan_lines("main.tf", lines)
        assert len(matches) >= 1

    def test_detect_api_key(self):
        lines = [
            '  api_key = "abcdef1234567890"',
        ]
        matches = self.detector.scan_lines("main.tf", lines)
        assert len(matches) >= 1

    def test_detect_connection_string(self):
        lines = [
            '  connection_string = "Server=tcp:myserver.database.windows.net;Database=mydb"',
        ]
        matches = self.detector.scan_lines("main.tf", lines)
        assert len(matches) >= 1

    def test_detect_sas_token(self):
        lines = [
            '  sas_token = "sv=2021-06-08&ss=bfqt&srt=sco"',
        ]
        matches = self.detector.scan_lines("main.tf", lines)
        assert len(matches) >= 1

    def test_detect_azure_storage_connection_string(self):
        lines = [
            '  value = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123"',
        ]
        matches = self.detector.scan_lines("main.tf", lines)
        assert len(matches) >= 1

    def test_no_false_positive_on_variable_reference(self):
        lines = [
            '  password = var.db_password',
        ]
        matches = self.detector.scan_lines("main.tf", lines)
        assert len(matches) == 0

    def test_no_false_positive_on_interpolation(self):
        lines = [
            '  password = "${var.db_password}"',
        ]
        matches = self.detector.scan_lines("main.tf", lines)
        assert len(matches) == 0

    def test_skip_comments(self):
        lines = [
            '  # password = "my-secret"',
            '  // api_key = "hardcoded"',
        ]
        matches = self.detector.scan_lines("main.tf", lines)
        assert len(matches) == 0

    def test_no_match_on_clean_code(self):
        lines = [
            'resource "azurerm_resource_group" "main" {',
            '  name     = "rg-myapp-prod-eastus2"',
            '  location = "eastus2"',
            '}',
        ]
        matches = self.detector.scan_lines("main.tf", lines)
        assert len(matches) == 0

    def test_detect_base64_encoded_value(self):
        long_base64 = "A" * 50 + "=="
        lines = [
            f'  value = "{long_base64}"',
        ]
        matches = self.detector.scan_lines("main.tf", lines)
        assert len(matches) >= 1

    def test_detect_account_key_pattern(self):
        lines = [
            '  value = "AccountKey=abcdefghijklmnopqrstuvwxyz0123456789=="',
        ]
        matches = self.detector.scan_lines("main.tf", lines)
        assert len(matches) >= 1

    def test_match_returns_correct_file_path(self):
        lines = ['  password = "hardcoded"']
        matches = self.detector.scan_lines("modules/db/main.tf", lines)
        assert len(matches) >= 1
        assert matches[0].file_path == "modules/db/main.tf"
