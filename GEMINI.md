# Threat Feed Aggregator Project

## Project Overview

This project is a web-based Threat Feed Aggregator built with Flask. Its purpose is to collect, process, and manage threat intelligence feeds from various sources. It allows users to define threat intelligence sources (URLs), specify their data format, and configure scheduling for automatic updates.

**Key Features & Enhancements:**
*   **Intelligent Processing:**
    *   **CIDR Aggregation:** Optimizes IP lists by merging contiguous IP addresses and smaller subnets into larger CIDR blocks.
    *   **Confidence Scoring:** Assigns a confidence score (0-100) to each source, influencing indicator risk scores.
    *   **Per-Source Aging/Retention:** Configurable retention periods for granular control over indicator lifespan.
*   **Diverse Threat Intelligence Sources:**
    *   **Extended Whitelist Sources:** Microsoft 365, GitHub Service IPs, Azure Public Cloud IPs.
    *   **STIX/TAXII Support:** Integration with industry-standard STIX/TAXII feeds for broader threat intelligence collection.
*   **Output Formatting:** Generates downloadable External Dynamic Lists (EDLs) for Palo Alto Networks and Fortinet.
*   **User Authentication:** Basic login functionality with optional LDAP integration.

## Recent Major Updates (v1.2)

### 1. Enhanced User Interface (Soft UI & Modern Design)
*   **Soft UI Theme:** Replaced the previous dark/cyberpunk theme with a clean, modern light "Soft UI" design, enhancing readability and aesthetics.
*   **Optimized Layout:** Redesigned the Dashboard layout for better visual hierarchy and module placement:
    *   Top: Modern statistical cards with icons.
    *   Middle: Threat Map and 30-Day Trend Chart, now stacked for better visibility.
    *   Main Column: Active Sources list and Job History.
    *   Side Column: Consolidated action cards (Add Source, External Intelligence Feeds, Exports, Access Control).
*   **Responsive Design:** Improved responsiveness for better display on various screen sizes.
*   **SweetAlert2 Integration:** Replaced standard browser alerts and confirms with modern, animated SweetAlert2 pop-ups for a better user experience.
*   **Interactive World Map:** Replaced the static country bar chart with an interactive jsVectorMap for visualizing threat origins.

### 2. Operational & Security Enhancements
*   **Dedicated System Settings Page:** Moved all system-level configurations (General Settings, SSL, LDAP, Admin Password, Backup/Restore) to a separate `/system` page, decluttering the main Dashboard.
*   **Feed Test Button:** Added a "Test Connection" button to feed configuration forms, allowing users to validate feed URLs and parsing settings before saving.
*   **Time-Based Trend Graphs:** Implemented historical data collection for total indicators, providing a 30-day trend chart on the Dashboard.
*   **Backup & Restore:** Added functionality for one-click backup of all critical data (`.db`, `config.json`, `safe_list.txt`) to a ZIP archive and restoration from a ZIP file via the System Settings page.
*   **Offline Mode:** All external CSS, JavaScript, and FontAwesome files are now hosted locally in `static/vendor/` directories, allowing the application to function fully without an internet connection.

## Getting Started

### 1. Local Development Setup

This project is a Python application. It uses a virtual environment for dependency management.

**a. Create and Activate Virtual Environment:**
```bash
python -m venv venv
```
Then activate it:
```bash
# On Windows (Command Prompt)
.\venv\Scripts\activate.bat

# On Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# On Linux/macOS
source venv/bin/activate
```

**b. Install Dependencies:**
Ensure your virtual environment is activated, then install the required packages:
```bash
pip install -r threat-feed-aggregator/requirements.txt
```

**c. Configure Environment Variables:**
Copy the example environment file and fill in your secrets.
```bash
cp .env.example .env
# Edit .env to set SECRET_KEY and ADMIN_PASSWORD
```

**d. Initialize Configuration (First Run):**
If `threat-feed-aggregator/threat_feed_aggregator/data/config.json` does not exist, copy the example:
```bash
cp threat-feed-aggregator/data/config.json.example threat-feed-aggregator/threat_feed_aggregator/data/config.json
```
_Note:_ The application is designed to automatically create `threat_feed.db` and `jobs.sqlite` on first run if they are missing.

**e. Run the Application:**
The Flask application can be run directly as a Python module. Ensure your virtual environment is activated.
```bash
python -m threat_feed_aggregator.app
```
The application will typically be accessible at `https://127.0.0.1:443`. You will see console output as the application starts and processes feeds. Your browser might warn about a self-signed certificate, which you can safely bypass for local development.

**Login Credentials:**
- Username: `admin`
- Password: (Set in your `.env` file, default `123456` if not set)

### 2. Docker Deployment

The project is configured for easy deployment using Docker.

**a. Environment Setup:**
Place your `.env` file (copied from `.env.example` with your secrets) in the project root (`EDL/`).

**b. Build and Run with Docker Compose:**
Navigate to the project root (`EDL/`) and run:
```bash
docker-compose up -d --build
```
This command will build the Docker image, create a container, and run it in detached mode.

**c. Access the Application:**
The application will be accessible via HTTPS at `https://localhost`. Your browser might warn about a self-signed certificate.

**d. Data Persistence:**
The `threat-feed-aggregator/data/` directory on your host machine is mapped as a Docker volume to `/app/threat_feed_aggregator/data` inside the container. This ensures your data persists even if the Docker container is removed or recreated.

**e. Stopping the Application:**
To stop the running container:
```bash
docker-compose down
```

### 3. OpenShift / Kubernetes Deployment

The application is configured for OpenShift/Kubernetes, prioritizing non-root execution and persistent storage.

**a. Build the Docker Image:**
First, build your Docker image and push it to an accessible registry (e.g., OpenShift's internal registry, Docker Hub, Quay.io).
```bash
docker build -t threat-feed-aggregator:latest ./threat-feed-aggregator
# Replace 'your-registry/your-project/threat-feed-aggregator:latest' with your actual registry path
docker tag threat-feed-aggregator:latest your-registry/your-project/threat-feed-aggregator:latest
docker push your-registry/your-project/threat-feed-aggregator:latest
```

**b. Deploy to OpenShift:**
1.  **Login to OpenShift:**
    ```bash
    oc login ...
    oc new-project threat-feed-aggregator-project # Or use an existing project
    ```
2.  **Update Deployment Manifest:**
    *   Open `openshift/deployment.yaml`.
    *   Update the `image:` field under `containers.threat-feed-aggregator` with the full path to your pushed image (e.g., `your-registry/your-project/threat-feed-aggregator:latest`).
3.  **Apply Manifests:**
    ```bash
    oc apply -f openshift/deployment.yaml
    ```
    This will create a `Secret` for credentials, a `PersistentVolumeClaim` for data, a `Deployment` to run the application, a `Service` for internal access, and a `Route` to expose it externally via HTTPS.

## Development Conventions

-   **Python Version:** The project uses Python 3.13.
-   **Web Framework:** Flask is used for the web interface.
-   **Scheduler:** APScheduler (with SQLAlchemyJobStore for persistence) is used for scheduling feed updates.
-   **Configuration:** `config.json` stores source URLs and application settings. `threat_feed.db` stores the aggregated unique indicators, whitelist, users, and job history.
-   **Code Structure:** The core logic is modularized within the `threat_feed_aggregator` package.
-   **Testing:** Unit tests are organized under the `tests/` directory.
-   **Version Control:** Git is used for version control.

## Cleanup for Transfer

To prepare the project for transfer to another PC, ensuring no personal data or temporary files are included:
1.  **Stop the Application:** If running, stop it first.
2.  **Delete Data Files:** Remove all database (`threat_feed.db`, `jobs.sqlite`), generated lists (`*.txt` in `data/`), and SSL certificates (`certs/`) from `threat-feed-aggregator/threat_feed_aggregator/data/` and `threat-feed-aggregator/threat_feed_aggregator/certs/` directories.
3.  **Remove Log Files:** Delete all `*.log` and `*.err` files from the project root.
4.  **Remove Example Config:** Delete `threat-feed-aggregator/threat_feed_aggregator/data/config.json` if it exists. Keep `config.json.example`.
5.  **Clean Python Cache:** Remove `__pycache__` and `.pytest_cache` directories.
6.  **Exclude `venv/`:** When copying the project, ensure you do not include the `venv/` (virtual environment) directory, as it is specific to your local machine.

## Building an Executable (Windows)

To create a standalone `.exe` file for easier deployment:
1.  **Install PyInstaller:** `pip install pyinstaller`
2.  **Build:** Run the command from the project root:
    ```bash
    pyinstaller --onefile --name threat-feed-aggregator --add-data "threat-feed-aggregator/threat_feed_aggregator/templates;threat_feed_aggregator/templates" --add-data "threat-feed-aggregator/threat_feed_aggregator/config;threat_feed_aggregator/config" --hidden-import="apscheduler.schedulers.background" --hidden-import="apscheduler.triggers.interval" threat-feed-aggregator/threat_feed_aggregator/app.py
    ```
3.  **Run:** The executable will be in the `dist/` folder. Ensure a `data/` folder exists next to it.
