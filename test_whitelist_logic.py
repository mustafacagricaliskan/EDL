import unittest
from threat_feed_aggregator.utils import filter_whitelisted_items
from threat_feed_aggregator.aggregator import _cleanup_whitelisted_items_from_db
from unittest.mock import patch, MagicMock

class TestWhitelistLogic(unittest.TestCase):

    def test_filter_whitelisted_items(self):
        items = ["1.1.1.1", "8.8.8.8", "10.0.0.5", "192.168.1.1"]
        whitelist = ["8.8.8.8", "10.0.0.0/8"]
        
        filtered = filter_whitelisted_items(items, whitelist)
        
        self.assertNotIn("8.8.8.8", filtered) # Exact match
        self.assertNotIn("10.0.0.5", filtered) # CIDR match
        self.assertIn("1.1.1.1", filtered)
        self.assertIn("192.168.1.1", filtered)
        print("test_filter_whitelisted_items PASSED")

    @patch('threat_feed_aggregator.aggregator.get_whitelist')
    @patch('threat_feed_aggregator.aggregator.get_all_indicators')
    @patch('threat_feed_aggregator.aggregator.db_delete_whitelisted_indicators')
    def test_cleanup_whitelisted_items_from_db(self, mock_delete, mock_get_indicators, mock_get_whitelist):
        # Setup mocks
        mock_get_whitelist.return_value = [{'item': '10.0.0.0/8'}]
        mock_get_indicators.return_value = {
            '1.1.1.1': {},
            '10.0.0.5': {},
            '10.1.2.3': {}
        }
        
        # Run function
        _cleanup_whitelisted_items_from_db()
        
        # Verify
        mock_delete.assert_called_once()
        args, _ = mock_delete.call_args
        deleted_list = args[0]
        
        self.assertIn('10.0.0.5', deleted_list)
        self.assertIn('10.1.2.3', deleted_list)
        self.assertNotIn('1.1.1.1', deleted_list)
        print("test_cleanup_whitelisted_items_from_db PASSED")

if __name__ == '__main__':
    unittest.main()
