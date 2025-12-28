# Facade for backward compatibility
from .repositories.user_repo import (
    add_admin_profile,
    add_ldap_group_mapping,
    add_local_user,
    check_admin_credentials,
    delete_admin_profile,
    delete_ldap_group_mapping,
    delete_local_user,
    get_admin_profiles,
    get_all_users,
    get_ldap_group_mappings,
    get_profile_by_ldap_groups,
    get_user_permissions,
    local_user_exists,
    set_admin_password,
    get_admin_password_hash,
    update_admin_profile,
    update_local_user_password,
    verify_local_user
)
from .repositories.indicator_repo import (
    get_country_stats,
    get_historical_stats,
    get_indicator_counts_by_type,
    get_unique_indicator_count,
    save_historical_stats,
    save_historical_stats as save_stats_history,
    upsert_indicators_bulk,
    remove_old_indicators,
    recalculate_scores,
    get_all_indicators,
    get_all_indicators_iter,
    clean_database_vacuum
)
from .repositories.job_repo import (
    clear_job_history,
    get_job_history,
    log_job_start,
    log_job_end
)
from .repositories.whitelist_repo import (
    add_whitelist_item,
    delete_whitelisted_indicators,
    get_whitelist,
    remove_whitelist_item,
    add_api_blacklist_item,
    remove_api_blacklist_item,
    get_api_blacklist_items
)
from .database.schema import init_db
from .database.connection import db_transaction, get_db_connection