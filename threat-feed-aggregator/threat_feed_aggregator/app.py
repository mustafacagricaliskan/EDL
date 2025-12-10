from flask import Flask, render_template, redirect, url_for, send_from_directory, request, jsonify, session
from functools import wraps
import os
import json
import threading

# It's important to import the main function from your script.
from .aggregator import main as run_aggregator
from .output_formatter import format_for_palo_alto, format_for_fortinet

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_COOKIE_NAME'] = 'threat_feed_aggregator_session'

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CONFIG_FILE = os.path.join(BASE_DIR, "config", "config.json")

STATS_FILE = os.path.join(BASE_DIR, "stats.json")

# Global variables
AGGREGATION_STATUS = "idle"  # idle, running, completed

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def read_config():
    if not os.path.exists(CONFIG_FILE):
        return {"source_urls": []}
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def write_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def read_stats():
    if not os.path.exists(STATS_FILE):
        return {}
    with open(STATS_FILE, "r") as f:
        try:
            stats = json.load(f)
            if isinstance(stats, dict):
                # Ensure all values are dictionaries
                for key, value in stats.items():
                    if not isinstance(value, dict):
                        stats[key] = {}
                return stats
        except json.JSONDecodeError:
            pass
    return {}

def write_stats(stats):
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f, indent=4)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != '123456':
            error = 'Invalid Credentials. Please try again.'
        else:
            session['logged_in'] = True
            session.modified = True
            print(f"Session after login: {session}")
            return redirect(url_for('index'))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    config = read_config()
    stats = read_stats()
    return render_template('index.html', config=config, urls=config.get("source_urls", []), stats=stats)

@app.route('/add', methods=['POST'])
@login_required
def add_url():
    name = request.form.get('name')
    url = request.form.get('url')
    data_format = request.form.get('format', 'text')
    key_or_column = request.form.get('key_or_column')
    
    if name and url:
        config = read_config()
        new_source = {"name": name, "url": url, "format": data_format}
        if key_or_column:
            new_source["key_or_column"] = key_or_column
        config["source_urls"].append(new_source)
        write_config(config)
    return redirect(url_for('index'))

@app.route('/update/<int:index>', methods=['POST'])
@login_required
def update_url(index):
    name = request.form.get('name')
    url = request.form.get('url')
    data_format = request.form.get('format', 'text')
    key_or_column = request.form.get('key_or_column')

    if name and url:
        config = read_config()
        if 0 <= index < len(config["source_urls"]):
            updated_source = {"name": name, "url": url, "format": data_format}
            if key_or_column:
                updated_source["key_or_column"] = key_or_column
            config["source_urls"][index] = updated_source
            write_config(config)
    return redirect(url_for('index'))

@app.route('/remove/<int:index>')
@login_required
def remove_url(index):
    config = read_config()
    if 0 <= index < len(config["source_urls"]):
        config["source_urls"].pop(index)
        write_config(config)
    return redirect(url_for('index'))

@app.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    lifetime = request.form.get('indicator_lifetime_days')
    if lifetime:
        config = read_config()
        config['indicator_lifetime_days'] = int(lifetime)
        write_config(config)
    return redirect(url_for('index'))

def aggregation_task():
    global AGGREGATION_STATUS
    
    config = read_config()
    source_urls = config.get("source_urls", [])
    
    results = run_aggregator(source_urls)
    stats = results.get("url_counts", {})
    stats["last_updated"] = datetime.now(timezone.utc).isoformat()
    write_stats(stats)
    
    processed_data = results.get("processed_data", [])

    # Format and save for Palo Alto
    palo_alto_output = format_for_palo_alto(processed_data)
    palo_alto_file_path = os.path.join(DATA_DIR, "palo_alto_edl.txt")
    with open(palo_alto_file_path, "w") as f:
        f.write(palo_alto_output)

    # Format and save for Fortinet
    fortinet_output = format_for_fortinet(processed_data)
    fortinet_file_path = os.path.join(DATA_DIR, "fortinet_edl.txt")
    with open(fortinet_file_path, "w") as f:
        f.write(fortinet_output)
    
    AGGREGATION_STATUS = "completed"

@app.route('/run')
@login_required
def run_script():
    global AGGREGATION_STATUS
    AGGREGATION_STATUS = "running"
    # Run the aggregation script in a separate thread to avoid blocking the web server
    thread = threading.Thread(target=aggregation_task)
    thread.start()
    return jsonify({"status": "running"})

@app.route('/status')
@login_required
def status():
    return jsonify({"status": AGGREGATION_STATUS})

@app.route('/data/<path:filename>')
@login_required
def download_file(filename):
    return send_from_directory(DATA_DIR, filename, as_attachment=True)
