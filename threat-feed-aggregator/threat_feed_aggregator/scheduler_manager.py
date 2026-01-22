import logging
import os
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from .config_manager import DATA_DIR, read_config

logger = logging.getLogger(__name__)

# Scheduler Initialization
db_type = os.getenv('DB_TYPE', 'sqlite')
if db_type == 'postgres':
    db_user = os.getenv('DB_USER', 'threat_user')
    db_pass = os.getenv('DB_PASS', 'secure_password')
    db_host = os.getenv('DB_HOST', 'postgres')
    db_port = os.getenv('DB_PORT', '5432')
    db_name = os.getenv('DB_NAME', 'threat_feed')
    db_url = f"postgresql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
    jobstores = {
        'default': SQLAlchemyJobStore(url=db_url)
    }
else:
    jobstores = {
        'default': SQLAlchemyJobStore(url=f'sqlite:///{os.path.join(DATA_DIR, "jobs.sqlite")}')
    }

scheduler = BackgroundScheduler(jobstores=jobstores)

def update_scheduled_jobs():
    """Refreshes the scheduler jobs based on current config."""
    from .aggregator import fetch_and_process_single_feed
    from .microsoft_services import process_microsoft_feeds
    from .github_services import process_github_feeds
    from .azure_services import process_azure_feeds

    config = read_config()
    configured_sources = {source['name']: source for source in config.get('source_urls', [])}

    scheduler.remove_all_jobs()

    for source_name, source_config in configured_sources.items():
        interval_minutes = source_config.get('schedule_interval_minutes')
        if interval_minutes:
            job_id = f"feed_fetch_{source_name}"
            scheduler.add_job(
                fetch_and_process_single_feed,
                'interval',
                minutes=interval_minutes,
                id=job_id,
                name=source_name,
                args=[source_config],
                replace_existing=True
            )
            logger.info(f"Scheduled job for {source_name} to run every {interval_minutes} minutes.")

    # Scheduled Service Updates (Every 24 hours)
    scheduler.add_job(process_microsoft_feeds, 'interval', minutes=1440, id='update_ms365', name='Microsoft 365 Feeds', replace_existing=True)
    scheduler.add_job(process_github_feeds, 'interval', minutes=1440, id='update_github', name='GitHub Feeds', replace_existing=True)
    scheduler.add_job(process_azure_feeds, 'interval', minutes=1440, id='update_azure', name='Azure Feeds', replace_existing=True)
    logger.info("Scheduled daily updates for Microsoft 365, GitHub, and Azure feeds.")

    # DNS Deduplication Schedule
    dedup_config = config.get('dns_dedup_schedule', {})
    if dedup_config.get('enabled', False):
        interval = dedup_config.get('interval_minutes', 60)
        scheduler.add_job(
            check_and_run_dns_dedup,
            'interval',
            minutes=interval,
            id='dns_deduplication_job',
            name='DNS Deduplication',
            replace_existing=True
        )
        logger.info(f"Scheduled DNS Deduplication check every {interval} minutes.")

def check_and_run_dns_dedup():
    """
    Checks if current time is within the allowed window and runs DNS Deduplication batch.
    """
    from datetime import datetime
    import asyncio
    from .services.dns_deduplication import process_background_dns_batch, run_deduplication_sweep
    
    config = read_config()
    conf = config.get('dns_dedup_schedule', {})
    
    if not conf.get('enabled', False):
        return

    now = datetime.now().time()
    start_str = conf.get('start_time', '00:00')
    end_str = conf.get('end_time', '23:59')
    
    try:
        start_time = datetime.strptime(start_str, '%H:%M').time()
        end_time = datetime.strptime(end_str, '%H:%M').time()
        
        # Check window
        in_window = False
        if start_time <= end_time:
            in_window = start_time <= now <= end_time
        else:
            in_window = start_time <= now or now <= end_time
            
        if in_window:
            try:
                # 1. Run Resolution Batch (Updates Cache)
                batch_size = conf.get('batch_size', 50)
                processed_count = asyncio.run(process_background_dns_batch(batch_size=batch_size))
                
                # 2. Run Deduplication Sweep (Checks Cache vs DB)
                # We run this if auto_delete is enabled. 
                # We can run it every time, or only if we processed something.
                # Running it every time ensures that if new IPs came from other feeds, 
                # we catch old domains matching them.
                if conf.get('auto_delete', False):
                    run_deduplication_sweep()
                    
                if processed_count > 0:
                     logger.info(f"Background DNS Task: Resolved {processed_count} domains.")
                     
            except Exception as e:
                logger.error(f"Background DNS Dedup failed: {e}")
            
    except ValueError:
        logger.error("Invalid time format in DNS Dedup Schedule config")
