import logging
import os
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from .config_manager import DATA_DIR, read_config

logger = logging.getLogger(__name__)

# Scheduler Initialization
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
