import unittest
import sqlite3
import json
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock DATA_DIR
import threat_feed_aggregator.config_manager
threat_feed_aggregator.config_manager.DATA_DIR = "." 

from threat_feed_aggregator.database.schema import init_db
from threat_feed_aggregator.repositories.indicator_repo import upsert_indicators_bulk, get_filtered_indicators_iter

class VerifyCustomEDLLogic(unittest.TestCase):
    def setUp(self):
        # Create an in-memory database for testing
        self.conn = sqlite3.connect(':memory:')
        self.conn.row_factory = sqlite3.Row
        init_db(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_source_filtering_accuracy(self):
        print("\n--- Starting Verification: Source Filtering ---")
        
        # 1. Setup Mock Data
        # Source 1: "Feodo Tracker" -> IP: 1.1.1.1, 2.2.2.2
        # Source 2: "URLHaus"       -> IP: 3.3.3.3, 2.2.2.2 (Overlap)
        # Source 3: "AlienVault"    -> IP: 4.4.4.4
        
        print("1. Seeding Database with Mock Sources...")
        upsert_indicators_bulk([("1.1.1.1", "US", "ip"), ("2.2.2.2", "DE", "ip")], source_name="Feodo Tracker", conn=self.conn)
        upsert_indicators_bulk([("3.3.3.3", "FR", "ip"), ("2.2.2.2", "DE", "ip")], source_name="URLHaus", conn=self.conn)
        upsert_indicators_bulk([("4.4.4.4", "UK", "ip")], source_name="AlienVault", conn=self.conn)

        # 2. Scenario A: Select ONLY "Feodo Tracker"
        # Expected: 1.1.1.1, 2.2.2.2
        # NOT Expected: 3.3.3.3, 4.4.4.4
        print("\n2. Scenario A: Filtering for 'Feodo Tracker' only")
        iterator_a = get_filtered_indicators_iter(["Feodo Tracker"], conn=self.conn)
        results_a = [row['indicator'] for row in iterator_a]
        print(f"   -> Retrieved: {sorted(results_a)}")
        
        self.assertIn("1.1.1.1", results_a, "Missing unique IP from Feodo")
        self.assertIn("2.2.2.2", results_a, "Missing shared IP from Feodo")
        self.assertNotIn("3.3.3.3", results_a, "Leakage: Found IP from URLHaus")
        self.assertNotIn("4.4.4.4", results_a, "Leakage: Found IP from AlienVault")
        print("   -> Scenario A: SUCCESS (Correctly filtered)")

        # 3. Scenario B: Select "URLHaus" and "AlienVault"
        # Expected: 3.3.3.3, 2.2.2.2 (from URLHaus), 4.4.4.4
        # NOT Expected: 1.1.1.1 (unique to Feodo)
        print("\n3. Scenario B: Filtering for 'URLHaus' + 'AlienVault'")
        iterator_b = get_filtered_indicators_iter(["URLHaus", "AlienVault"], conn=self.conn)
        results_b = [row['indicator'] for row in iterator_b]
        print(f"   -> Retrieved: {sorted(results_b)}")
        
        self.assertIn("3.3.3.3", results_b)
        self.assertIn("4.4.4.4", results_b)
        self.assertIn("2.2.2.2", results_b, "Should include shared IP because it is in URLHaus")
        self.assertNotIn("1.1.1.1", results_b, "Leakage: Found unique IP from Feodo")
        print("   -> Scenario B: SUCCESS (Correctly combined sources)")

if __name__ == '__main__':
    unittest.main()
