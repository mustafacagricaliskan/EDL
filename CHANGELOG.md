# Changelog

## [1.14.0] - 2026-01-16

### Added
- **Threat Analysis Center:** A comprehensive new module (`/analysis`) for deep-diving into threat intelligence data.
    - **Advanced Filtering:** FortiGate-style "Filter Bar" allowing multiple criteria (Source, Tag, Type, Country, Risk Level).
    - **Smart Autocomplete:** Dynamic suggestions for filter values (e.g., typing "Fe..." suggests "Feodo Tracker").
    - **Auto-Tagging:** Indicators are automatically tagged (e.g., "Botnet", "Malware", "Phishing") based on their source.
    - **Risk Scoring:** Visual progress bars for risk scores and automatic level assignment (Critical, High, Medium, Low).
- **Server-Side Pagination:** Implemented efficient database queries (`LIMIT/OFFSET`) to handle millions of records in the analysis view without browser lag.

### Optimized
- **Batch Processing:** Optimized the analysis service to use "Batch Source Fetching", solving the N+1 query problem and significantly improving page load times.
- **Memory Management:** Refactored the Whitelist cleanup process to use iterators and chunked processing, preventing high RAM usage during maintenance tasks.
- **Dashboard Architecture:** Refactored `index.html` (Overview) to extend the unified `base.html` template, eliminating code duplication and ensuring UI consistency across all tabs.

### Fixed
- **UI Glitches:** Fixed alignment issues in the DataTables "Show entries" dropdown where the arrow was overlapping the text.
- **Filter Logic:** Improved "Risk Score" filtering to support intuitive operators (e.g., entering "80" implies ">= 80").
- **Navigation:** Fixed the issue where the "Risk Analysis" sidebar link would disappear when navigating to the Overview page.

## [1.13.1] - 2026-01-16

### Fixed
- **Parsing Logic:** Updated `DOMAIN_PATTERN` regex to support modern Top-Level Domains (TLDs) longer than 6 characters (e.g., `.online`, `.cloud`, `.istanbul`). This fixes the issue where sources like USOM were showing 0 indicators.
- **Whitelist Logic:** Fixed a bug in `is_whitelisted` where the global text-based safe list (`safe_list.txt`) was being ignored for domain indicators.
- **Database Performance:** Optimized `save_batch` in the aggregator to use a single database transaction for bulk inserts, significantly improving performance and stability when processing massive feeds (100k+ items).

## [1.13.0] - 2026-01-16