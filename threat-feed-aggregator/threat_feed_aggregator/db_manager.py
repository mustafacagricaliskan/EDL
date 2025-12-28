# Facade for backward compatibility
from .database.connection import get_db_connection, db_transaction, DB_WRITE_LOCK
from .database.schema import init_db
from .repositories.user_repo import (
    set_admin_password, get_admin_password_hash, check_admin_credentials,
    get_all_users, add_local_user, update_local_user_password, delete_local_user,
    verify_local_user, local_user_exists,
    get_admin_profiles, add_admin_profile, delete_admin_profile, update_admin_profile,
    get_user_permissions,
    get_ldap_group_mappings, add_ldap_group_mapping, delete_ldap_group_mapping,
    get_profile_by_ldap_groups
)
from .repositories.indicator_repo import (
    upsert_indicators_bulk, clean_database_vacuum, get_all_indicators_iter,
    recalculate_scores, get_all_indicators, remove_old_indicators,
    get_unique_indicator_count, get_indicator_counts_by_type, get_country_stats,
    save_historical_stats, get_historical_stats
)
from .repositories.whitelist_repo import (
    add_whitelist_item, get_whitelist, remove_whitelist_item,
    add_api_blacklist_item, get_api_blacklist_items, remove_api_blacklist_item,
    delete_whitelisted_indicators
)
from .repositories.job_repo import (
    log_job_start, log_job_end, get_job_history, clear_job_history
)