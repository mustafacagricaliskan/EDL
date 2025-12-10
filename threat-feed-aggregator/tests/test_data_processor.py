import unittest
import sys
import os
from datetime import datetime, timezone

# Add the src directory to the Python path
from threat_feed_aggregator.data_processor import process_data

class TestDataProcessor(unittest.TestCase):

    def test_process_data_empty_input(self):
        db = {}
        processed_db, count = process_data("", db)
        self.assertEqual(processed_db, {})
        self.assertEqual(count, 0)

    def test_process_data_add_new_items(self):
        db = {}
        raw_data = "item1\nitem2"
        processed_db, count = process_data(raw_data, db)
        self.assertIn("item1", processed_db)
        self.assertIn("item2", processed_db)
        self.assertIn("last_seen", processed_db["item1"])
        self.assertEqual(count, 2)

    def test_process_data_update_existing_items(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        db = {"item1": {"last_seen": "2023-01-01T00:00:00Z"}}
        raw_data = "item1"
        processed_db, count = process_data(raw_data, db)
        self.assertNotEqual(processed_db["item1"]["last_seen"], "2023-01-01T00:00:00Z")
        self.assertEqual(count, 1)

    def test_process_data_with_comments_and_empty_lines(self):
        db = {}
        raw_data = "# comment\nitem1\n\nitem2\n  # another comment"
        processed_db, count = process_data(raw_data, db)
        self.assertIn("item1", processed_db)
        self.assertIn("item2", processed_db)
        self.assertNotIn("# comment", processed_db)
        self.assertEqual(count, 2)

if __name__ == '__main__':
    unittest.main()
