import unittest
from unittest.mock import patch, MagicMock
import os
import json
from threat_feed_aggregator.auth_manager import check_credentials, read_config

# Ensure a dummy config file exists for testing read_config
DUMMY_CONFIG_DIR = os.path.join(os.path.dirname(__file__), "temp_auth_config")
DUMMY_CONFIG_PATH = os.path.join(DUMMY_CONFIG_DIR, "config.json")

class TestAuthManager(unittest.TestCase):

    @patch('threat_feed_aggregator.auth_manager.check_admin_credentials')
    def test_local_admin_login_success(self, mock_check_admin_credentials):
        mock_check_admin_credentials.return_value = True
        success, message = check_credentials('admin', 'correct_password')
        self.assertTrue(success)
        self.assertEqual(message, "Local admin login successful.")
        mock_check_admin_credentials.assert_called_once_with('correct_password')

    @patch('threat_feed_aggregator.auth_manager.check_admin_credentials')
    def test_local_admin_login_failure(self, mock_check_admin_credentials):
        mock_check_admin_credentials.return_value = False
        success, message = check_credentials('admin', 'wrong_password')
        self.assertFalse(success)
        self.assertEqual(message, "Invalid admin password.")
        mock_check_admin_credentials.assert_called_once_with('wrong_password')

    @patch('threat_feed_aggregator.auth_manager.read_config')
    def test_ldap_disabled(self, mock_read_config):
        mock_read_config.return_value = {'auth': {'ldap': {'enabled': False}}}
        # Since 'admin' is checked first, need to ensure it fails to reach LDAP check
        with patch('threat_feed_aggregator.auth_manager.check_admin_credentials', return_value=False):
            success, message = check_credentials('non_admin_user', 'password')
            self.assertFalse(success)
            self.assertEqual(message, "Invalid Credentials.") # Falls back to generic message

    @patch('threat_feed_aggregator.auth_manager.read_config')
    def test_ldap_enabled_not_configured(self, mock_read_config):
        mock_read_config.return_value = {'auth': {'ldap': {'enabled': True, 'server': '', 'domain': ''}}} # Empty server/domain
        with patch('threat_feed_aggregator.auth_manager.check_admin_credentials', return_value=False):
            success, message = check_credentials('user', 'password')
            self.assertFalse(success)
            self.assertEqual(message, "LDAP not fully configured.")

    @patch('threat_feed_aggregator.auth_manager.read_config')
    @patch('threat_feed_aggregator.auth_manager.Connection')
    @patch('threat_feed_aggregator.auth_manager.Server')
    def test_ldap_login_success(self, mock_server, mock_connection, mock_read_config):
        mock_read_config.return_value = {
            'auth': {'ldap': {'enabled': True, 'server': 'ldap.example.com', 'domain': 'dc=example,dc=com'}}
        }
        mock_conn_instance = MagicMock()
        mock_conn_instance.bound = True
        mock_connection.return_value = mock_conn_instance

        with patch('threat_feed_aggregator.auth_manager.check_admin_credentials', return_value=False):
            success, message = check_credentials('testuser', 'ldappassword')
            self.assertTrue(success)
            self.assertEqual(message, "LDAP login successful.")
            mock_server.assert_called_once_with('ldap.example.com', get_info=unittest.mock.ANY)
            mock_connection.assert_called_once_with(mock_server.return_value, user='uid=testuser,ou=people,dc=example,dc=com', password='ldappassword', auto_bind=True)
            mock_conn_instance.unbind.assert_called_once()

    @patch('threat_feed_aggregator.auth_manager.read_config')
    @patch('threat_feed_aggregator.auth_manager.Connection')
    @patch('threat_feed_aggregator.auth_manager.Server')
    def test_ldap_login_failure(self, mock_server, mock_connection, mock_read_config):
        mock_read_config.return_value = {
            'auth': {'ldap': {'enabled': True, 'server': 'ldap.example.com', 'domain': 'dc=example,dc=com'}}
        }
        mock_conn_instance = MagicMock()
        mock_conn_instance.bound = False
        mock_conn_instance.result = {'description': 'invalidCredentials'}
        mock_connection.return_value = mock_conn_instance

        with patch('threat_feed_aggregator.auth_manager.check_admin_credentials', return_value=False):
            success, message = check_credentials('testuser', 'wrongpassword')
            self.assertFalse(success)
            self.assertEqual(message, "Invalid LDAP credentials.")
            mock_connection.assert_called_once()
            mock_conn_instance.unbind.assert_not_called() # Should not unbind if not bound

    @patch('threat_feed_aggregator.auth_manager.read_config')
    @patch('threat_feed_aggregator.auth_manager.Connection', side_effect=Exception("LDAP connection error"))
    @patch('threat_feed_aggregator.auth_manager.Server')
    def test_ldap_login_exception(self, mock_server, mock_connection, mock_read_config):
        mock_read_config.return_value = {
            'auth': {'ldap': {'enabled': True, 'server': 'ldap.example.com', 'domain': 'dc=example,dc=com'}}
        }
        with patch('threat_feed_aggregator.auth_manager.check_admin_credentials', return_value=False):
            success, message = check_credentials('testuser', 'password')
            self.assertFalse(success)
            self.assertEqual(message, "LDAP authentication error.")
            mock_connection.assert_called_once()

    @patch('threat_feed_aggregator.auth_manager.read_config')
    def test_no_auth_methods_succeed(self, mock_read_config):
        mock_read_config.return_value = {'auth': {'ldap': {'enabled': False}}} # LDAP disabled
        # No local admin check for 'user' username
        with patch('threat_feed_aggregator.auth_manager.check_admin_credentials', return_value=False):
            success, message = check_credentials('non_admin_user', 'any_password')
            self.assertFalse(success)
            self.assertEqual(message, "Invalid Credentials.")

    @patch('threat_feed_aggregator.auth_manager.read_config')
    @patch('threat_feed_aggregator.auth_manager.Connection')
    @patch('threat_feed_aggregator.auth_manager.Server')
    def test_ldap_login_success_with_upn(self, mock_server, mock_connection, mock_read_config):
        mock_read_config.return_value = {
            'auth': {'ldap': {'enabled': True, 'server': 'ldap.example.com', 'domain': 'dc=example,dc=com'}}
        }
        mock_conn_instance = MagicMock()
        mock_conn_instance.bound = True
        mock_connection.return_value = mock_conn_instance

        with patch('threat_feed_aggregator.auth_manager.check_admin_credentials', return_value=False):
            success, message = check_credentials('testuser@example.com', 'ldappassword')
            self.assertTrue(success)
            self.assertEqual(message, "LDAP login successful.")
            mock_server.assert_called_once_with('ldap.example.com', get_info=unittest.mock.ANY)
            mock_connection.assert_called_once_with(mock_server.return_value, user='testuser@example.com', password='ldappassword', auto_bind=True)
            mock_conn_instance.unbind.assert_called_once()

# New test class for read_config to better isolate patching CONFIG_FILE
class TestReadConfig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.makedirs(DUMMY_CONFIG_DIR, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(DUMMY_CONFIG_PATH):
            os.remove(DUMMY_CONFIG_PATH)
        if os.path.exists(DUMMY_CONFIG_DIR):
            os.rmdir(DUMMY_CONFIG_DIR)

    def setUp(self):
        # Ensure dummy config is empty or reset before each test
        with open(DUMMY_CONFIG_PATH, "w") as f:
            f.write("{}")

    @patch('threat_feed_aggregator.auth_manager.CONFIG_FILE', DUMMY_CONFIG_PATH)
    def test_read_config_file_not_found(self):
        os.remove(DUMMY_CONFIG_PATH) # Ensure file does not exist
        config = read_config()
        self.assertEqual(config, {})

    @patch('threat_feed_aggregator.auth_manager.CONFIG_FILE', DUMMY_CONFIG_PATH)
    def test_read_config_json_decode_error(self):
        # Write invalid JSON to dummy config file
        with open(DUMMY_CONFIG_PATH, "w") as f:
            f.write("invalid json")
        
        config = read_config()
        self.assertEqual(config, {})

    @patch('threat_feed_aggregator.auth_manager.CONFIG_FILE', DUMMY_CONFIG_PATH)
    def test_read_config_success(self):
        test_config_content = {"auth": {"ldap": {"enabled": True}}}
        with open(DUMMY_CONFIG_PATH, "w") as f:
            json.dump(test_config_content, f)
        
        config = read_config()
        self.assertEqual(config, test_config_content)