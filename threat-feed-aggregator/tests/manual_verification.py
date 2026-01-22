import sys
import os
import asyncio
import logging

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Ensure we can import from the app
sys.path.append('/app')

def check_indexes():
    logger.info("--- CHECKING INDEXES ---")
    try:
        from threat_feed_aggregator.database.connection import get_db_connection, DB_TYPE
        
        conn = get_db_connection()
        indexes = []
        
        if DB_TYPE == 'postgres':
            cursor = conn.execute("SELECT indexname FROM pg_indexes WHERE tablename = 'indicators'")
            indexes = [row['indexname'] for row in cursor.fetchall()]
        else:
            cursor = conn.execute("PRAGMA index_list('indicators')")
            indexes = [row['name'] for row in cursor.fetchall()]
            
        logger.info(f"Found indexes on 'indicators': {indexes}")
        
        required = ['idx_indicators_type', 'idx_indicators_country']
        missing = [idx for idx in required if idx not in indexes]
        
        if missing:
            logger.error(f"MISSING INDEXES: {missing}")
            # Optional: Attempt to create them? No, let schema.py handle it on restart.
        else:
            logger.info("All required indexes present.")
            
    except Exception as e:
        logger.error(f"Index check failed: {e}")

async def test_dns_dedup():
    logger.info("--- TESTING DNS DEDUPLICATION (Mock) ---")
    try:
        import aiodns
        logger.info(f"aiodns version: {aiodns.__version__}")
        
        # Test basic resolution
        loop = asyncio.get_running_loop()
        resolver = aiodns.DNSResolver(loop=loop)
        
        domain = 'google.com'
        logger.info(f"Resolving {domain}...")
        result = await resolver.query(domain, 'A')
        ips = [r.host for r in result]
        logger.info(f"Resolved IPs: {ips}")
        
        if not ips:
            logger.error("Resolution failed (empty result).")
        else:
            logger.info("DNS Resolution OK.")
            
    except Exception as e:
        logger.error(f"DNS Test Failed: {e}")

async def main():
    check_indexes()
    await test_dns_dedup()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"Main loop error: {e}")
