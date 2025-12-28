# Changelog

## [1.9.0] - 2025-12-28

### Added
- **Repository Pattern:** Major backend refactoring separating database logic into domain-specific repositories (Users, Indicators, Whitelist, Jobs).
- **Service Layer:** Introduced a service layer to isolate business logic from web routes for improved maintainability.
- **Configurable Timezone:** Added a global system timezone setting in the GUI, ensuring all timestamps across the dashboard and logs reflect the local time.
- **Enhanced IP Investigation:** Integrated `ip-api.com` for detailed geolocation, ISP, and ASN data in the investigation tool.
- **Dynamic Dashboard Refresh:** Added high-frequency polling and AJAX-driven updates for summary cards and task results.
- **Downloadable Service Whitelists:** Added dropdown menus to the dashboard for direct downloading of MS365, GitHub, and Azure generated lists.

### Improved
- **Clean Code Architecture:** Extracted all dashboard JavaScript into a dedicated `static/js/dashboard.js` file.
- **Live Log Intelligence:** Expanded the "Hide Polls" filter to exclude static assets, login requests, and root heartbeat pings.
- **UI Layout:** Equalized the dimensions of the "Recent Task Activity" and "Scheduled Runs" modules for a balanced layout.
- **Robust Error Handling:** Added comprehensive error reporting and notifications for all AJAX operations.

### Fixed
- **Security:** Upgraded Gunicorn to v23.0.0 to resolve a critical TE.CL request smuggling vulnerability (CVE-2024-1135) related to improper 'Transfer-Encoding' header validation.
- **CSRF Protection:** Resolved issues with missing CSRF tokens in AJAX-submitted forms.
- **Stats Corruption:** Fixed a bug in the stats manager that was corrupting non-dictionary configuration values.
- **Healthcheck:** Updated Docker healthcheck to support HTTPS/SSL environments.

## [1.8.0] - 2025-12-28

### Improved
- **Dashboard UI:** Enhanced "Scheduled Runs" visibility by displaying relative time (e.g., "in 15 min") and using descriptive feed names instead of internal function IDs.
- **Testing Suite:** Added comprehensive unit tests for `Tools`, `System`, and `Data` routes, achieving >95% coverage for core functionality.
- **Scheduler Transparency:** Jobs are now named after their source feed (e.g., "FireHol Level 1") for easier monitoring.

### Fixed
- **Test Infrastructure:** Resolved import errors and mocking issues in `test_auth_manager.py` and `test_gui_views.py`.
- **Dependencies:** Added `python-whois` to `requirements.txt` to fix runtime errors in the investigation tool.

## [1.7.0] - 2025-12-27

### Added
- **Enterprise RBAC System:** Full Role-Based Access Control allowing custom profiles with Module-specific permissions (None, Read, Read-Write).
- **LDAP Group-to-Profile Mapping:** Dynamic mapping of multiple LDAP Group DNs to specific administrative roles.
- **Unified Modern UI:** Global "Base Layout" with a permanent sidebar, responsive containers, and a tabbed "System Settings" interface.
- **Live Log Intelligence:** Added filtering ("Hide Polls") and persistent activity tracking to the operational terminal.

### Optimized (Performance)
- **Database Engine:** Optimized `upsert_indicators_bulk` using temporary staging tables and mass SELECT-INSERT logic for 5x faster processing.
- **GeoIP Singleton:** Implemented a singleton MaxMind reader and LRU caching (10k entries) to eliminate redundant disk I/O during feed enrichment.
- **Memory Streaming:** Updated EDL generation to use iterators, significantly reducing RAM usage for million-record datasets.
- **Whitelist O(1):** Redesigned whitelist checking using pre-computed network objects and sets for near-instant lookup speeds.

### Fixed
- **SQLite Compatibility:** Fixed "near DO: syntax error" by replacing modern UPSERT with backward-compatible logic for older SQLite versions.
- **UI Desync:** Ensured the "Recent Task Activity" table and "Live Logs" update immediately after manual triggers.
- **Config Persistence:** Final fix for the issue where DNS and Proxy settings would occasionally overwrite each other.

## [1.6.0] - 2025-12-27

### Added
- **Local User Management:** Implemented a full user management system allowing administrators to add, delete, and manage passwords for multiple local users, not just the default 'admin'.
- **Connection Status Indicators:** Added real-time visual badges (Online/Offline) for LDAP, DNS, and Proxy configurations in the System Settings dashboard.
- **Config Caching:** Implemented in-memory caching with mtime invalidation for the configuration file, significantly reducing disk I/O and improving UI response times.
- **HTTP Session Reuse:** Optimized the data collector to reuse a single `aiohttp.ClientSession` across all feed fetches, reducing TCP/TLS handshake overhead.

### Fixed
- **Config Persistence Bug:** Resolved a critical issue where saving DNS settings would overwrite or disable Proxy settings (and vice versa) due to race conditions and incorrect file paths.
- **Proxy Save UX:** Fixed an issue where the Proxy "Save" button would not trigger the form submission correctly. Added a "Saving..." visual feedback.
- **Windows Docker Volume:** Switched from atomic rename to direct file writing for configuration saves to ensure compatibility with Windows Docker volumes.

### Changed
- **UX Workflow:** Updated settings pages to redirect back to the specific settings tab instead of the dashboard after saving changes.

## [1.5.1] - 2025-12-27

### Fixed
- **LDAP Syntax Error:** Fixed a critical `SyntaxError` in `auth_manager.py` related to backslash escaping in f-strings that caused the container to crash loop during startup.
- **Active Directory Parsing:** Corrected the username parsing logic for `DOMAIN\User` formats.

### Added
- **Live LDAP Testing:** Updated the System Settings UI and Backend to allow testing LDAP credentials and server configurations instantly, without needing to save them first.
- **Enhanced Debugging:** Added verbose `[v1.5.1]` logging for LDAP connection attempts to aid in troubleshooting authentication issues.

## [1.5.0] - 2025-12-25

### Added
- **Multi-Client API Access:** Replaced single API key with a robust client management system. Supports generating unique keys for multiple clients (SOAR, SIEM, etc.).
- **Trusted Host Restrictions:** Added ability to restrict API access per client to specific IP addresses.
- **Proxy Support:** Implemented system-wide HTTP/HTTPS proxy configuration (Server, Port, Auth) via System Settings.
- **LDAP Group Authorization:** Added "Admin Group DN" setting to restrict login access to specific LDAP groups.
- **Certificate Management UI:** Improved feedback loops for SSL certificate uploads.
- **Data Normalization:** Automatic lowercase normalization for Domains and standardization for IPs/CIDRs to prevent duplicates.

### Changed
- **API Authentication:** Updated `api_key_required` decorator to validate against the new client list and enforce IP restrictions.
- **Data Parsers:** Enhanced CSV, JSON, and Text parsers to normalize data before database insertion.
- **System Settings UI:** Complete overhaul of the "API Access" card and addition of "Proxy Settings" card.

### Fixed
- **Duplicate Prevention:** Implemented stricter normalization logic to ensure the deduplication mechanism (DB constraints + CIDR aggregation) works flawlessly across all feed sources.

### Operations
- **Docker:** Updated Docker build to include all new dependencies and configuration structures.
