import logging
from datetime import datetime

from flask import render_template

from ..config_manager import read_config, read_stats
from ..db_manager import get_country_stats, get_indicator_counts_by_type, get_unique_indicator_count, get_whitelist
from ..utils import SAFE_ITEMS, format_timestamp
from . import bp_dashboard
from .auth import login_required

logger = logging.getLogger(__name__)

@bp_dashboard.route('/')
@login_required
def index():
    config = read_config()
    stats = read_stats()

    total_indicator_count = get_unique_indicator_count()
    indicator_counts_by_type = get_indicator_counts_by_type()
    country_stats = get_country_stats()
    whitelist = get_whitelist()

    # Sort safe list for display
    safe_list_sorted = sorted(list(SAFE_ITEMS))

    # Format timestamps
    formatted_stats = {}
    for key, value in stats.items():
        if isinstance(value, dict) and 'last_updated' in value:
            formatted_stats[key] = {**value, 'last_updated': format_timestamp(value['last_updated'])}
        elif key == 'last_updated':
            formatted_stats[key] = format_timestamp(value)
        else:
            formatted_stats[key] = value

    # Scheduler access
    import pytz

    from ..app import scheduler

    target_tz = pytz.timezone(config.get('timezone', 'UTC'))
    scheduled_jobs = scheduler.get_jobs()
    jobs_for_template = []

    from apscheduler.triggers.interval import IntervalTrigger

    for job in scheduled_jobs:
        next_run = job.next_run_time.astimezone(target_tz) if job.next_run_time else None
        time_until = 'N/A'
        if next_run:
            now = datetime.now(target_tz)
            diff = next_run - now
            total_seconds = int(diff.total_seconds())
            minutes = total_seconds // 60
            if minutes < 60:
                time_until = f"in {minutes} min"
            else:
                hours = minutes // 60
                mins = minutes % 60
                time_until = f"in {hours}h {mins}m"

        jobs_for_template.append({
            'id': job.id,
            'name': job.name,
            'next_run_time': next_run.strftime('%d/%m/%Y %H:%M') if next_run else 'N/A',
            'time_until': time_until,
            'interval': f"{job.trigger.interval.total_seconds() / 60} minutes" if isinstance(job.trigger, IntervalTrigger) else 'N/A'
        })

    return render_template('index.html', config=config, urls=config.get("source_urls", []), stats=formatted_stats, scheduled_jobs=jobs_for_template, total_indicator_count=total_indicator_count, indicator_counts_by_type=indicator_counts_by_type, whitelist=whitelist, country_stats=country_stats, safe_list=safe_list_sorted)

@bp_dashboard.route('/data/<path:filename>')
@login_required
def download_file(filename):
    from flask import send_from_directory

    from ..config_manager import DATA_DIR
    return send_from_directory(DATA_DIR, filename, as_attachment=True)
