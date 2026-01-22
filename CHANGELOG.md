# Changelog

## [1.15.0] - 2026-01-22

### Added
- **DNS Deduplication V2:** Re-architected for performance using background batch processing and database caching to prevent network floods.
- **UI Improvements:** Modernized DNS Deduplication dashboard with live logs, improved settings layout, and real-time status.
- **Security:** Added "Confirm Password" validation field for local user creation and password changes.

### Fixed
- **Startup:** Resolved container startup hang caused by synchronous DB index creation on large tables; moved index creation to background thread.
- **Azure:** Fixed SSL certificate verification error during Azure feed downloads (bypassed verification for compatibility).
- **LDAP:** Fixed invalid server address error by ensuring container uses internal DNS servers.
- **System:** Fixed CSRF token missing error in Group Mapping forms by implementing global token handling.
- **Core:** Fixed missing imports in API routes causing failures in Microsoft 365 feed updates.

## [1.14.1] - 2026-01-16

### Fixed
- **DataTables Layout:** Reverted the pagination layout to the classic bottom-aligned style based on user feedback.
- **Pagination Logic:** Verified and ensured `full_numbers` pagination is used for better navigation on large datasets.
- **Filter Editing:** Fixed an issue where clicking on a filter chip would not populate the correct values in the dropdown if special characters were present.

## [1.14.0] - 2026-01-16

### Added
- **Threat Analysis Center:** A comprehensive new module (`/analysis`) for deep-diving into threat intelligence data.
    - **Advanced Filtering:** FortiGate-style "Filter Bar" allowing multiple criteria (Source, Tag, Type, Country, Risk Level).
    - **Smart Autocomplete:** Dynamic suggestions for filter values.
    - **Auto-Tagging:** Indicators are automatically tagged based on their source.
    - **Risk Scoring:** Visual progress bars for risk scores.
- **Server-Side Pagination:** Implemented efficient database queries (`LIMIT/OFFSET`).

### Optimized
- **Batch Processing:** Optimized the analysis service to use "Batch Source Fetching", solving the N+1 query problem.
- **Memory Management:** Refactored the Whitelist cleanup process.
- **Dashboard Architecture:** Refactored `index.html` to extend the unified `base.html` template.

### Fixed
- **UI Glitches:** Fixed alignment issues in the DataTables "Show entries" dropdown.
- **Filter Logic:** Improved "Risk Score" filtering to support intuitive operators (>=, <, etc.).
- **Navigation:** Fixed the issue where the "Risk Analysis" sidebar link would disappear.

## [1.13.1] - 2026-01-16
