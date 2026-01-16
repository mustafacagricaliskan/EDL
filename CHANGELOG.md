# Changelog

## [1.13.1] - 2026-01-16

### Fixed
- **Parsing Logic:** Updated `DOMAIN_PATTERN` regex to support modern Top-Level Domains (TLDs) longer than 6 characters (e.g., `.online`, `.cloud`, `.istanbul`). This fixes the issue where sources like USOM were showing 0 indicators.
- **Whitelist Logic:** Fixed a bug in `is_whitelisted` where the global text-based safe list (`safe_list.txt`) was being ignored for domain indicators.
- **Database Performance:** Optimized `save_batch` in the aggregator to use a single database transaction for bulk inserts, significantly improving performance and stability when processing massive feeds (100k+ items).

## [1.13.0] - 2026-01-16

### Added
- **Custom EDL Manager:** A powerful new feature allowing users to create, save, and manage custom External Dynamic Lists. Users can select specific sources and types (IP/Domain/URL) to generate a persistent, token-protected API endpoint.
- **Internal Threat Database Search:** Added a new tool in the Investigation page that searches only the local threat database. It displays which feed source an indicator belongs to and when it was last seen.
- **Search History:** Implemented a persistent "Recent Searches" history for both external and internal investigation tools, stored locally in the browser.
- **Optimized Performance:** Introduced major backend optimizations including smarter score recalculation (incremental updates instead of full table scans) and memory-efficient data streaming for EDL generation.

### Improved
- **Investigation UI:** Redesigned the "IP Investigation" page to clearly separate External (OSINT) and Internal (Local DB) search tools.
- **Dashboard Accuracy:** Fixed a long-standing issue where dashboard counters and "Last Update" timestamps were not updating in real-time due to file-system caching. Now directly queries the database for live accuracy.
- **System Reliability:** Added missing database commits for custom lists, ensuring saved configurations persist across restarts.

### Fixed
- **JavaScript Issues:** Resolved a critical syntax error in the investigation page that caused search buttons to become unresponsive.
- **Data Persistence:** Fixed a bug where creating or deleting custom lists would appear successful but revert after a refresh.

## [1.11.0] - 2026-01-08
