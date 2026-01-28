from flask import Flask, flash, render_template, send_from_directory, url_for, request, redirect, jsonify, session, get_flashed_messages
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup
import os
import re
import glob
import urllib.parse
import subprocess
import threading
from werkzeug.utils import secure_filename
from flask_session import Session
import logging
import hashlib
import json
import time
import uuid
from urllib.parse import urlparse


app = Flask(__name__)
app.secret_key = "2ff991db03acbf28d5ca077b6fa76288e0e8d5f9a18c6743"
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

LEASE_START_DATE = datetime(2024, 12, 3)
MILES_ALLOWED_PER_YEAR = 15000
LEASE_YEARS = 3
MILES_ALLOWED_TOTAL = MILES_ALLOWED_PER_YEAR * LEASE_YEARS
DAYS_IN_LEASE = (LEASE_YEARS * 365) + (LEASE_YEARS // 4)  # Account for leap year
MILES_PER_DAY = MILES_ALLOWED_TOTAL / DAYS_IN_LEASE
STARTING_MILES = 22

TORRENT_WATCH_DIR = '/mnt/synology/misc/to_download'

PIN = "5201"  # Change this to your desired 4-digit PIN

# Set up logging
logger = logging.getLogger('flask_app')
logger.setLevel(logging.DEBUG)
# Add console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Define maximum lengths
MAX_FILENAME_LENGTH = 100
MAX_PATH_LENGTH = 255
TIMESTAMP_LENGTH = 10  # e.g., 10 digits for timestamp

# Define the path to the mileage data file
DATA_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mileage_data.json')
BLOCKED_DEVICES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blocked_devices.json')

# Initialize a lock for thread-safe file operations
data_lock = threading.Lock()

# Pushover configuration
PUSHOVER_API_TOKEN = "a4488f14hpvaa8qwyhgcxh49f8s2s9"
PUSHOVER_USER_KEY = "ur9Rjzm3ewdx1V5Ub1g75YaPZB6PR2"
BLOCKED_IPS_FILE = "blocked_ips.json"
MAX_FAILED_ATTEMPTS = 3
INITIAL_BLOCK_DURATION = 3600  # 1 hour in seconds
MAX_BLOCK_DURATION = 86400 * 7  # 1 week in seconds

class DownloadManager:
    def __init__(self):
        self.downloads = {}  # Dictionary to store download tasks
        self.lock = threading.Lock()
        self.status_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'download_status.json')
        self.load_status()

    def load_status(self):
        """Load download statuses from file"""
        try:
            if os.path.exists(self.status_file):
                with open(self.status_file, 'r') as f:
                    self.downloads = json.load(f)
                logger.debug(f"Loaded {len(self.downloads)} downloads from status file")
        except Exception as e:
            logger.error(f"Error loading download status: {e}")
            self.downloads = {}

    def save_status(self):
        """Save download statuses to file"""
        try:
            # Don't save process objects to file
            serializable_downloads = {}
            for download_id, download in self.downloads.items():
                serializable_download = dict(download)
                serializable_download.pop('process', None)
                serializable_downloads[download_id] = serializable_download
            
            with open(self.status_file, 'w') as f:
                json.dump(serializable_downloads, f)
            logger.debug(f"Saved {len(serializable_downloads)} downloads to status file")
        except Exception as e:
            logger.error(f"Error saving download status: {e}")

    def add_download(self, url):
        """Add a new download task"""
        download_id = str(uuid.uuid4())
        with self.lock:
            self.downloads[download_id] = {
                'url': url,
                'status': 'pending',
                'progress': 0,
                'start_time': time.time(),
                'end_time': None,
                'error': None,
                'filename': None,
                'process': None
            }
            self.save_status()
            logger.debug(f"Added download {download_id} for URL: {url}")
        return download_id

    def update_status(self, download_id, status, progress=0, error=None, filename=None):
        """Update download status"""
        with self.lock:
            if download_id in self.downloads:
                self.downloads[download_id].update({
                    'status': status,
                    'progress': progress,
                    'error': error,
                    'filename': filename
                })
                if status in ['completed', 'failed', 'cancelled']:
                    self.downloads[download_id]['end_time'] = time.time()
                self.save_status()

    def cancel_download(self, download_id):
        """Cancel a download task"""
        with self.lock:
            if download_id in self.downloads:
                download = self.downloads[download_id]
                process = download.get('process')
                
                if process and process.poll() is None:
                    try:
                        # Try graceful termination first
                        process.terminate()
                        # Wait a bit for graceful termination
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            # Force kill if it doesn't terminate gracefully
                            process.kill()
                            process.wait()
                        
                        self.update_status(download_id, 'cancelled')
                        return True
                    except Exception as e:
                        logger.error(f"Error terminating process for download {download_id}: {e}")
                        # Still mark as cancelled even if process termination failed
                        self.update_status(download_id, 'cancelled')
                        return True
                else:
                    # No active process, just mark as cancelled
                    self.update_status(download_id, 'cancelled')
                    return True
        return False

    def get_downloads(self):
        """Get all download tasks"""
        with self.lock:
            return self.downloads.copy()

# Initialize the download manager
download_manager = DownloadManager()







def load_mileage():
    """
    Load the current miles from the JSON data file.
    If the file doesn't exist or is corrupted, return STARTING_MILES.
    """
    with data_lock:
        if not os.path.exists(DATA_FILE_PATH):
            return STARTING_MILES
        try:
            with open(DATA_FILE_PATH, 'r') as f:
                data = json.load(f)
                return data.get('current_miles', STARTING_MILES)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading mileage data: {e}")
            return STARTING_MILES

def save_mileage(miles):
    """
    Save the current miles to the JSON data file.
    """
    with data_lock:
        try:
            with open(DATA_FILE_PATH, 'w') as f:
                json.dump({'current_miles': miles}, f)
        except IOError as e:
            logger.error(f"Error saving mileage data: {e}")

# Initialize current_miles from the data file
current_miles = load_mileage()

def generate_short_hash(s, length=6):
    return hashlib.md5(s.encode()).hexdigest()[:length]

def validate_url(url):
    """
    Validates if a URL is properly formatted and has a valid scheme.
    """
    if not url or not isinstance(url, str):
        return False

    try:
        parsed = urlparse(url.strip())
        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            return False
        # Must be http or https
        if parsed.scheme.lower() not in ['http', 'https']:
            return False
        return True
    except Exception:
        return False

def parse_yt_dlp_output(output):
    """
    Parses yt-dlp's JSON output to extract the downloaded file path.
    """
    try:
        data = json.loads(output)
        return data.get('filepath') or data.get('filename') or data.get('_filename')
    except json.JSONDecodeError:
        logger.error("Failed to decode yt-dlp JSON output.")
        return None

@app.before_request
def require_pin():
    allowed_endpoints = ['login', 'static', 'mileage_tracker', 'download', 'download_status', 'cancel_download', 'most_recent_file', 'test_json', 'serve_file', 'upload', 'update_channels']  # Use view function names
    logger.debug(f"Request to endpoint: {request.endpoint}, authenticated: {'authenticated' in session}")
    
    if 'authenticated' not in session and request.endpoint not in allowed_endpoints:
        logger.debug(f"Redirecting unauthenticated request to {request.endpoint}")
        # Store the original path for redirect after login
        # Get the path from the request URL
        next_path = request.path
        # If there's a query string, preserve it
        if request.query_string:
            next_path += '?' + request.query_string.decode('utf-8')
        login_url = f"https://blandfx.com/files/login?next={urllib.parse.quote(next_path)}"
        return redirect(login_url)
    
    logger.debug(f"Allowing request to {request.endpoint}")

def load_blocked_ips():
    try:
        with open(BLOCKED_IPS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"blocked_ips": {}}

def save_blocked_ips(data):
    with open(BLOCKED_IPS_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def is_ip_blocked(ip):
    blocked_ips = load_blocked_ips()
    if ip in blocked_ips["blocked_ips"]:
        block_time = blocked_ips["blocked_ips"][ip]
        if time.time() - block_time < INITIAL_BLOCK_DURATION:
            return True
        else:
            # Remove expired block
            del blocked_ips["blocked_ips"][ip]
            save_blocked_ips(blocked_ips)
    return False

def block_ip(ip):
    blocked_ips = load_blocked_ips()
    blocked_ips["blocked_ips"][ip] = time.time()
    save_blocked_ips(blocked_ips)
    
    # Send Pushover notification
    message = f"IP {ip} has been blocked due to multiple failed login attempts"
    requests.post(
        "https://api.pushover.net/1/messages.json",
        data={
            "token": PUSHOVER_API_TOKEN,
            "user": PUSHOVER_USER_KEY,
            "message": message,
            "title": "File Share - IP Blocked"
        }
    )

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

# Dictionary to store failed attempts per IP
failed_attempts = {}

def generate_device_id():
    """Generate a unique device ID based on various browser characteristics"""
    components = [
        request.user_agent.string,
        request.headers.get('Accept-Language', ''),
        request.headers.get('Accept-Encoding', ''),
        request.headers.get('DNT', ''),
        request.headers.get('Upgrade-Insecure-Requests', ''),
    ]
    # Add IP as a component but not the only one
    components.append(request.remote_addr)
    
    # Create a hash of all components
    device_hash = hashlib.sha256('|'.join(str(c) for c in components).encode()).hexdigest()
    return device_hash

def load_blocked_devices():
    try:
        with open(BLOCKED_DEVICES_FILE, 'r') as f:
            data = json.load(f)
            # Ensure the data structure is correct
            if "blocked_devices" not in data:
                data = {"blocked_devices": {}}
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return {"blocked_devices": {}}

def save_blocked_devices(data):
    # Ensure the data structure is correct
    if "blocked_devices" not in data:
        data = {"blocked_devices": data}
    with open(BLOCKED_DEVICES_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def is_device_blocked(device_id):
    blocked_devices = load_blocked_devices()
    if device_id in blocked_devices["blocked_devices"]:
        block_info = blocked_devices["blocked_devices"][device_id]
        if time.time() - block_info["block_time"] < block_info["duration"]:
            return True
        else:
            # Remove expired block
            del blocked_devices["blocked_devices"][device_id]
            save_blocked_devices(blocked_devices)
    return False

def block_device(device_id, ip, failed_attempts):
    blocked_devices = load_blocked_devices()
    
    # Calculate block duration based on number of previous blocks
    previous_blocks = blocked_devices["blocked_devices"].get(device_id, {}).get("block_count", 0)
    duration = min(INITIAL_BLOCK_DURATION * (2 ** previous_blocks), MAX_BLOCK_DURATION)
    
    blocked_devices["blocked_devices"][device_id] = {
        "block_time": time.time(),
        "duration": duration,
        "ip": ip,
        "user_agent": request.user_agent.string,
        "block_count": previous_blocks + 1,
        "last_attempt": datetime.now().isoformat()
    }
    save_blocked_devices(blocked_devices)
    
    # Send Pushover notification with more details
    message = f"""
Device blocked due to multiple failed login attempts:
IP: {ip}
User Agent: {request.user_agent.string}
Block Duration: {timedelta(seconds=duration)}
Previous Blocks: {previous_blocks}
    """
    requests.post(
        "https://api.pushover.net/1/messages.json",
        data={
            "token": PUSHOVER_API_TOKEN,
            "user": PUSHOVER_USER_KEY,
            "message": message.strip(),
            "title": "File Share - Device Blocked"
        }
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        device_id = generate_device_id()
        ip = request.remote_addr
        
        # Check if device is blocked
        if is_device_blocked(device_id):
            flash('Too many failed attempts. Please try again later.', 'error')
            return render_template('login.html')
        
        pin = request.form['pin']
        if pin == PIN:
            # Reset failed attempts on successful login
            if device_id in failed_attempts:
                del failed_attempts[device_id]
            session['authenticated'] = True
            
            # Redirect to the original path if provided, otherwise go to files home
            next_path = request.form.get('next') or request.args.get('next')
            if next_path:
                # Decode the URL-encoded path
                next_path = urllib.parse.unquote(next_path)
                # Ensure the path starts with /
                if not next_path.startswith('/'):
                    next_path = '/' + next_path
                # Ensure the path starts with /files (since all routes are under /files)
                if not next_path.startswith('/files'):
                    next_path = '/files' + next_path
                # Build the full URL
                redirect_url = f"https://blandfx.com{next_path}"
                logger.debug(f"Redirecting authenticated user to: {redirect_url}")
                return redirect(redirect_url)
            return redirect('https://blandfx.com/files/')
        else:
            # Increment failed attempts
            failed_attempts[device_id] = failed_attempts.get(device_id, 0) + 1
            
            if failed_attempts[device_id] >= MAX_FAILED_ATTEMPTS:
                block_device(device_id, ip, failed_attempts[device_id])
                flash('Too many failed attempts. Your device has been blocked.', 'error')
            else:
                flash(f'Invalid PIN. Please try again. {MAX_FAILED_ATTEMPTS - failed_attempts[device_id]} attempts remaining.', 'error')
    return render_template('login.html')

@app.route('/unblock_ip/<ip>')
def unblock_ip(ip):
    if 'authenticated' not in session:
        return redirect('https://blandfx.com/files/login')
    
    blocked_ips = load_blocked_ips()
    if ip in blocked_ips["blocked_ips"]:
        del blocked_ips["blocked_ips"][ip]
        save_blocked_ips(blocked_ips)
        flash(f'IP {ip} has been unblocked.', 'success')
    else:
        flash(f'IP {ip} is not blocked.', 'error')
    return redirect(url_for('view_blocked_ips'))

@app.route('/mileage', methods=['GET', 'POST'])
def mileage_tracker():
    global current_miles  # Reference the global variable
    if request.method == 'POST':
        data = request.get_json()
        miles = data.get('miles')
        if miles is not None:
            try:
                miles = float(miles)
                if miles < 0:
                    raise ValueError("Miles cannot be negative.")
                current_miles = miles
                save_mileage(current_miles)  # Save to disk
                return jsonify({"status": "success"})
            except (ValueError, TypeError):
                return jsonify({"status": "error", "message": "Invalid miles value."}), 400
        else:
            return jsonify({"status": "error", "message": "Miles value is required."}), 400

    today = datetime.now()
    # Adjust days_elapsed to include the first day
    days_elapsed = max((today - LEASE_START_DATE).days + 1, 1)  # Ensure at least day 1
    allowed_miles = STARTING_MILES + (days_elapsed * MILES_PER_DAY)
    surplus = allowed_miles - current_miles  # surplus = allowed_miles - current_miles

    # Format the date as "Today: MM-DD-YYYY"
    formatted_date = today.strftime('Today: %m-%d-%Y')

    return render_template(
        'mileage.html',
        surplus=surplus,
        date=formatted_date,
        miles=current_miles,
        lease_day=days_elapsed,
        allowed_miles=allowed_miles
    )

@app.context_processor
def utility_processor():
    def format_size(size_in_bytes):
        size_in_mb = size_in_bytes / (1024 * 1024)
        if size_in_mb >= 1:
            # For files 1MB and larger, show in MB rounded to nearest whole number
            if size_in_mb < 1024:
                return f"{round(size_in_mb)} MB"
            else:
                # For files 1GB and larger, show in GB with one decimal place
                size_in_gb = size_in_mb / 1024
                return f"{size_in_gb:.1f} GB"
        else:
            # For files under 1MB, show in KB rounded to nearest whole number
            size_in_kb = size_in_bytes / 1024
            return f"{round(size_in_kb)} KB"
    return dict(format_size=format_size)

@app.route('/download', methods=['GET', 'POST'])
def download():
    if request.method == 'POST':
        try:
            url = request.form.get('url', '').strip()
            custom_filename = request.form.get('filename', '').strip()
            logger.debug(f"Download request received for URL: {url}")

            if not url:
                logger.warning("Empty URL provided for download")
                return jsonify({'status': 'error', 'message': 'Please enter a URL'})

            # Validate URL format
            if not validate_url(url):
                logger.warning(f"Invalid URL format provided: {url}")
                return jsonify({'status': 'error', 'message': 'Invalid URL format. Please provide a valid HTTP or HTTPS URL.'})

            # Add new download task
            download_id = download_manager.add_download(url)
            logger.debug(f"Created download task with ID: {download_id}")

            def download_task(custom_filename):
                    try:
                        # Update status to downloading immediately
                        download_manager.update_status(download_id, 'downloading', progress=0)

                        output_template = '/mnt/synology/misc/media/%(title).100s.%(ext)s'
                        command = f'yt-dlp --progress --no-part --restrict-filenames --print-json -o "{output_template}" {url}'

                        process = subprocess.Popen(
                            command, shell=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
                        )

                        with download_manager.lock:
                            download_manager.downloads[download_id]['process'] = process

                        # Regex to capture download percentage
                        progress_regex = re.compile(r'\[download\]\s+([0-9\.]+)%')

                        stdout_output = ""
                        start_time = time.time()
                        last_progress_time = start_time
                        has_started_downloading = False

                        if process.stdout:
                            for line in iter(process.stdout.readline, ''):
                                current_time = time.time()
                                stdout_output += line

                                # Check for timeout (30 minutes max)
                                if current_time - start_time > 30 * 60:
                                    logger.error(f"Download {download_id} timed out")
                                    download_manager.update_status(download_id, 'failed', error='Download timed out after 30 minutes')
                                    process.terminate()
                                    try:
                                        process.wait(timeout=5)
                                    except subprocess.TimeoutExpired:
                                        process.kill()
                                    return

                                match = progress_regex.search(line)
                                if match:
                                    has_started_downloading = True
                                    percentage = float(match.group(1))
                                    download_manager.update_status(download_id, 'downloading', progress=percentage)
                                    last_progress_time = current_time

                                # Check if the process has been cancelled
                                with download_manager.lock:
                                    if download_manager.downloads[download_id].get('status') == 'cancelled':
                                        break

                        # Wait for process to complete with timeout
                        try:
                            process.wait(timeout=30)  # 30 second timeout for process completion
                        except subprocess.TimeoutExpired:
                            logger.error(f"Process for download {download_id} didn't complete within timeout")
                            download_manager.update_status(download_id, 'failed', error='Process timeout')
                            process.kill()
                            return

                        # Check if yt-dlp failed immediately (common with invalid URLs)
                        if process.returncode != 0 and not has_started_downloading:
                            logger.error(f"yt-dlp failed immediately for {download_id}, likely invalid URL. Output: {stdout_output[:500]}")
                            download_manager.update_status(download_id, 'failed', error=f'Invalid URL or unsupported content: {stdout_output.strip()[:200]}')
                            return

                        if process.returncode == 0:
                            # Find the JSON line in the output
                            json_line = None
                            for line in reversed(stdout_output.strip().split('\n')):
                                if line.strip().startswith('{') and line.strip().endswith('}'):
                                    json_line = line
                                    break

                            if json_line:
                                downloaded_filepath = parse_yt_dlp_output(json_line)
                                if downloaded_filepath:
                                    file_name, file_extension = os.path.splitext(os.path.basename(downloaded_filepath))
                                    
                                    if custom_filename:
                                        # Use the custom filename but keep the original extension
                                        sanitized_file_name = secure_filename(custom_filename)
                                    else:
                                        # Use the default yt-dlp naming logic
                                        cleaned_file_name = clean_filename(file_name, MAX_FILENAME_LENGTH)
                                        first_words = first_four_words(cleaned_file_name)
                                        sanitized_file_name = urlify(first_words, MAX_FILENAME_LENGTH)
                                    
                                    if not sanitized_file_name:
                                        sanitized_file_name = 'default_filename'
                                    
                                    sanitized_file_name = sanitized_file_name[:MAX_FILENAME_LENGTH]
                                    new_file_path = os.path.join(
                                        os.path.dirname(downloaded_filepath),
                                        f"{sanitized_file_name}{file_extension}"
                                    )
                                    
                                    if os.path.exists(new_file_path):
                                        hash_suffix = generate_short_hash(sanitized_file_name)
                                        sanitized_file_name = f"{sanitized_file_name}_{hash_suffix}"
                                        new_file_path = os.path.join(
                                            os.path.dirname(downloaded_filepath),
                                            f"{sanitized_file_name}{file_extension}"
                                        )
                                    
                                    os.rename(downloaded_filepath, new_file_path)
                                    
                                    # Set modification time to current time so new downloads appear at top of file list
                                    current_time = time.time()
                                    os.utime(new_file_path, (current_time, current_time))
                                    
                                    # Check if conversion is needed
                                    def check_if_conversion_needed():
                                        try:
                                            command = f'ffprobe -v error -select_streams v:0 -show_entries stream=codec_name -of default=noprint_wrappers=1:nokey=1 "{new_file_path}"'
                                            codec = subprocess.check_output(command, shell=True).decode('utf-8').strip()
                                            return codec != 'h264'
                                        except:
                                            return False
                                    
                                    needs_conversion = check_if_conversion_needed()
                                    
                                    if needs_conversion:
                                        download_manager.update_status(download_id, 'converting', 100, filename=new_file_path)
                                        thread = threading.Thread(target=check_and_convert_to_x264, args=(new_file_path, download_id))
                                        thread.start()
                                    else:
                                        download_manager.update_status(download_id, 'completed', 100, filename=new_file_path)
                                else:
                                    download_manager.update_status(download_id, 'failed', error='Failed to extract filename from JSON')
                            else:
                                download_manager.update_status(download_id, 'failed', error='Failed to retrieve downloaded filename from yt-dlp output')
                        else:
                            # Check if the download was cancelled before marking it as failed
                            with download_manager.lock:
                                if download_manager.downloads[download_id].get('status') != 'cancelled':
                                    download_manager.update_status(download_id, 'failed', error=stdout_output)
                    except Exception as e:
                        logger.error(f"Error in download task for {download_id}: {e}")
                        with download_manager.lock:
                            if download_manager.downloads[download_id].get('status') != 'cancelled':
                                download_manager.update_status(download_id, 'failed', error=str(e))

            thread = threading.Thread(target=download_task, args=(custom_filename,))
            thread.start()

            logger.debug(f"Download thread started for {download_id}")
            return jsonify({'status': 'started', 'download_id': download_id})
        except Exception as e:
            logger.error(f"Error in download route: {e}")
            return jsonify({'status': 'error', 'message': f'Internal error: {str(e)}'})
    
    # Get current downloads for display - show active and converting downloads
    all_downloads = download_manager.get_downloads()
    active_downloads = {
        download_id: download 
        for download_id, download in all_downloads.items() 
        if download.get('status') in ['pending', 'downloading', 'converting']
    }
    return render_template('download.html', downloads=active_downloads, editable_extensions=list(EDITABLE_EXTENSIONS))

@app.route('/download/status/<download_id>')
def download_status(download_id):
    """Get status of a specific download"""
    downloads = download_manager.get_downloads()
    logger.debug(f"Status request for {download_id}. Available downloads: {list(downloads.keys())}")
    
    if download_id in downloads:
        # Remove 'process' key before returning
        status = dict(downloads[download_id])
        status.pop('process', None)
        logger.debug(f"Returning status for {download_id}: {status}")
        return jsonify(status)
    
    logger.warning(f"Download {download_id} not found. Available: {list(downloads.keys())}")
    return jsonify({'status': 'not_found'}), 404

@app.route('/download/cancel/<download_id>', methods=['POST'])
def cancel_download(download_id):
    """Cancel a download"""
    try:
        if download_manager.cancel_download(download_id):
            return jsonify({'status': 'cancelled'})
        return jsonify({'status': 'error', 'message': 'Download not found or already completed'}), 404
    except Exception as e:
        logger.error(f"Error cancelling download {download_id}: {e}")
        return jsonify({'status': 'error', 'message': 'Internal error'}), 500

@app.route('/test-json')
def test_json():
    """Simple test endpoint to verify JSON responses work"""
    return jsonify({'status': 'test', 'message': 'JSON response working'})

# Define editable extensions
EDITABLE_EXTENSIONS = {'.txt', '.conf', '.m3u', '.m3u8', '.ini', '.json', '.md', '.xml', '.yaml', '.yml', '.sh', '.py', '.css', '.js', '.html'}

@app.route('/')
@app.route('/files')
def list_files():
    """Handle file listing - requires authentication."""
    if 'authenticated' not in session:
        return redirect('https://blandfx.com/files/login')
    
    directory_path = '/mnt/synology/misc/media/'  # Update this path to the path of your NAS directory
    # Correctly locate ignore.txt in the application's root directory
    app_dir = os.path.dirname(os.path.abspath(__file__))
    ignore_file_path = os.path.join(app_dir, 'ignore.txt')

    ignored_files = set()
    if os.path.isfile(ignore_file_path):
        with open(ignore_file_path, 'r') as f:
            ignored_files = {line.strip() for line in f if line.strip()}

    files = os.listdir(directory_path)
    files_with_details = [
        {
            'name': f,
            'edit_url': url_for('submit_text', filename=f) if any(f.endswith(ext) for ext in EDITABLE_EXTENSIONS) else None,
            'size': os.path.getsize(os.path.join(directory_path, f)),
            'mtime': os.path.getmtime(os.path.join(directory_path, f))
        } for f in files if os.path.isfile(os.path.join(directory_path, f)) and f not in ignored_files
    ]
    files_sorted = sorted(files_with_details, key=lambda x: x['mtime'], reverse=True)
    return render_template('files.html', files=files_sorted)

@app.route('/files/<path:filename>')
def serve_file(filename):
    """Serve specific files - no authentication required."""
    directory_path = '/mnt/synology/misc/media/'  # Update this path to the path of your NAS directory
    # Correctly locate ignore.txt in the application's root directory
    app_dir = os.path.dirname(os.path.abspath(__file__))
    ignore_file_path = os.path.join(app_dir, 'ignore.txt')

    ignored_files = set()
    if os.path.isfile(ignore_file_path):
        with open(ignore_file_path, 'r') as f:
            ignored_files = {line.strip() for line in f if line.strip()}

    decoded_filename = urllib.parse.unquote(filename)
    safe_path = os.path.join(directory_path, decoded_filename)

    if os.path.isfile(safe_path) and decoded_filename not in ignored_files:
        # Serve all files normally without transcoding
        logger.info(f"Serving file: {safe_path}")
        actual_filename = os.path.basename(safe_path)
        directory = os.path.dirname(safe_path)
        return send_from_directory(directory, actual_filename)

    return "File not found.", 404

@app.route('/rename/<path:old_filename>', methods=['POST'])
@app.route('/files/rename/<path:old_filename>', methods=['POST'])
def rename_file(old_filename):
    if 'authenticated' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    new_filename = data.get('new_name')

    if not new_filename:
        return jsonify({'success': False, 'error': 'New filename not provided'}), 400

    base_path = '/mnt/synology/misc/media/'
    old_filepath = os.path.join(base_path, old_filename)
    new_filepath = os.path.join(base_path, new_filename)

    # Basic security checks
    if not os.path.abspath(old_filepath).startswith(base_path) or \
       not os.path.abspath(new_filepath).startswith(base_path):
        return jsonify({'success': False, 'error': 'Invalid path'}), 400

    if not os.path.exists(old_filepath):
        return jsonify({'success': False, 'error': 'File not found'}), 404
    
    if os.path.exists(new_filepath):
        return jsonify({'success': False, 'error': 'A file with the new name already exists'}), 409

    try:
        # Get the original modification time
        original_mtime = os.path.getmtime(old_filepath)

        # Rename the file
        os.rename(old_filepath, new_filepath)

        # Apply the original modification time to the new file
        os.utime(new_filepath, (original_mtime, original_mtime))
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error renaming file from {old_filepath} to {new_filepath}: {e}")
        return jsonify({'success': False, 'error': 'Failed to rename file'}), 500

@app.route('/delete/<path:filename>', methods=['DELETE'])
@app.route('/files/delete/<path:filename>', methods=['DELETE'])
def delete_file(filename):
    if 'authenticated' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    base_path = '/mnt/synology/misc/media/'
    filepath = os.path.join(base_path, filename)

    if not os.path.abspath(filepath).startswith(base_path):
        return jsonify({'success': False, 'error': 'Invalid path'}), 400

    if not os.path.exists(filepath):
        return jsonify({'success': False, 'error': 'File not found'}), 404

    try:
        os.remove(filepath)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting file {filepath}: {e}")
        return jsonify({'success': False, 'error': 'Failed to delete file'}), 500

@app.route('/notes', methods=['GET', 'POST'])
@app.route('/files/notes', methods=['GET', 'POST'])
def submit_text():
    if 'authenticated' not in session:
        return redirect('https://blandfx.com/files/login')

    filename = request.args.get('filename', '')
    content = ''
    directory_path = '/mnt/synology/misc/media/'

    if filename:
        safe_filename = secure_filename(filename)
        file_path = os.path.join(directory_path, safe_filename)
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
            except Exception as e:
                flash(f"Error reading file: {e}", "danger")
                return redirect(url_for('list_files'))
        else:
            flash(f"File '{safe_filename}' not found. Starting a new note.", "warning")
            filename = '' # Reset filename to treat as a new note

    if request.method == 'POST':
        content = request.form.get('content', '')
        # Use original_filename to track the file being edited
        original_filename = request.form.get('original_filename', filename)
        new_filename = request.form.get('new_filename', original_filename)
        is_auto_save = request.form.get('auto_save', '').lower() == 'true'

        # If it is a new note and the filename is empty, generate a new one
        if not original_filename and not new_filename.strip():
            now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            new_filename = f"note_{now}.txt"
        else:
            # Only append .txt if no extension is present
            name, ext = os.path.splitext(new_filename)
            if not ext:
                new_filename += '.txt'

        safe_new_filename = secure_filename(new_filename)
        new_filepath = os.path.join(directory_path, safe_new_filename)

        # Prevent overwriting existing files on rename or new file creation
        # For autosave of new files, allow overwriting since it's the same session
        should_prevent_overwrite = (not original_filename or original_filename != safe_new_filename) and os.path.exists(new_filepath)
        if should_prevent_overwrite and not (is_auto_save and not original_filename):
            flash(f"A file named '{safe_new_filename}' already exists.", "danger")
            return render_template('notes.html', content=content, filename=original_filename or new_filename)

        # If the filename has changed, remove the old file
        if original_filename and original_filename != safe_new_filename:
            old_filepath = os.path.join(directory_path, secure_filename(original_filename))
            if os.path.exists(old_filepath):
                os.remove(old_filepath)

        try:
            with open(new_filepath, 'w') as f:
                f.write(content)

            if is_auto_save:
                # For autosave, return JSON response
                return jsonify({
                    'success': True,
                    'message': f"Note '{safe_new_filename}' auto-saved successfully!",
                    'filename': safe_new_filename
                })
            else:
                # For regular save, show flash message and redirect
                flash(f"Note '{safe_new_filename}' saved successfully!", "success")
                return redirect(url_for('list_files'))

        except Exception as e:
            if is_auto_save:
                # For autosave, return JSON error response
                return jsonify({
                    'success': False,
                    'message': f"Error saving note: {str(e)}"
                }), 500
            else:
                # For regular save, show flash message and render template
                flash(f"Error saving note: {e}", "danger")
                return render_template('notes.html', content=content, filename=safe_new_filename)

    return render_template('notes.html', content=content, filename=filename)

@app.route('/upload', methods=['POST'])
@app.route('/files/upload', methods=['POST'])
def upload_file():
    """Handle file uploads from drag and drop or paste operations"""
    upload_start_time = time.time()
    logger.info(f"[Upload] Received upload request from {request.remote_addr}")
    
    if 'authenticated' not in session:
        logger.warning(f"[Upload] Unauthorized upload attempt from {request.remote_addr}")
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    try:
        if 'file' not in request.files:
            logger.warning(f"[Upload] No file in request")
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        logger.info(f"[Upload] Received file: {file.filename}")
        
        if file.filename == '':
            logger.warning(f"[Upload] Empty filename")
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Secure the filename
        filename = secure_filename(file.filename)
        if not filename:
            # Generate a filename if none provided
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"uploaded_file_{timestamp}"
            logger.info(f"[Upload] Generated filename: {filename}")
        
        # Ensure unique filename
        directory_path = '/mnt/synology/misc/media/'
        file_path = os.path.join(directory_path, filename)
        counter = 1
        original_filename = filename
        while os.path.exists(file_path):
            name, ext = os.path.splitext(original_filename)
            filename = f"{name}_{counter}{ext}"
            file_path = os.path.join(directory_path, filename)
            counter += 1
        
        if counter > 1:
            logger.info(f"[Upload] Renamed to avoid collision: {filename}")
        
        # Save the file
        logger.info(f"[Upload] Saving file to: {file_path}")
        save_start = time.time()
        file.save(file_path)
        save_duration = time.time() - save_start
        
        # Get file size
        file_size = os.path.getsize(file_path)
        logger.info(f"[Upload] File saved successfully. Size: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB), Save time: {save_duration:.2f}s")
        
        # Set modification time to current time so new uploads appear at top of file list
        current_time = time.time()
        os.utime(file_path, (current_time, current_time))
        
        total_duration = time.time() - upload_start_time
        logger.info(f"[Upload] Upload complete: {filename}, Total time: {total_duration:.2f}s")
        return jsonify({'success': True, 'filename': filename})
        
    except Exception as e:
        logger.error(f"[Upload] Error uploading file: {e}", exc_info=True)
        return jsonify({'success': False, 'error': f'Upload failed: {str(e)}'}), 500

@app.route('/most_recent_file')
def most_recent_file():
    directory_path = '/mnt/synology/misc/media/'
    ignore_file_path = os.path.join(directory_path, 'ignore.txt')

    ignored_files = set()
    if os.path.isfile(ignore_file_path):
        with open(ignore_file_path, 'r') as f:
            ignored_files = {line.strip() for line in f if line.strip()}

    files = os.listdir(directory_path)
    files_with_ctime = [
        {
            'name': f,
            'ctime': os.path.getctime(os.path.join(directory_path, f))
        } for f in files if os.path.isfile(os.path.join(directory_path, f)) and f not in ignored_files
    ]

    if not files_with_ctime:
        return "No files found.", 404

    most_recent_file = max(files_with_ctime, key=lambda x: x['ctime'])
    most_recent_file_url = f"https://blandfx.com/media/{urllib.parse.quote(most_recent_file['name'])}"

    return jsonify({'url': most_recent_file_url})

def clean_filename(filename, max_length=MAX_FILENAME_LENGTH):
    # Remove emojis and special characters
    filename = re.sub(r'[^\w\s-]', '', filename)
    # Replace multiple spaces with a single space
    filename = re.sub(r'\s+', ' ', filename)
    cleaned = filename.strip()
    return cleaned[:max_length] if cleaned else 'default_filename'

def urlify(s, max_length=MAX_FILENAME_LENGTH):
    # Remove any remaining non-alphanumeric characters (except spaces and hyphens)
    s = re.sub(r'[^\w\s-]', '', s)
    # Replace spaces with hyphens
    s = re.sub(r'\s+', '-', s)
    sanitized = s.lower().strip('-')
    return sanitized[:max_length] if sanitized else 'default-file'

def first_four_words(s):
    words = s.split()
    return ' '.join(words[:4])

def check_and_convert_to_x264(file_path, download_id=None):
    try:
        # Store the original modification time to preserve it for new downloads
        original_mtime = os.path.getmtime(file_path)
        
        # Check the codec of the file
        command = f'ffprobe -v error -select_streams v:0 -show_entries stream=codec_name -of default=noprint_wrappers=1:nokey=1 "{file_path}"'
        logger.debug(f"Running command: {command}")
        codec = subprocess.check_output(command, shell=True).decode('utf-8').strip()
        logger.debug(f"Codec found: {codec}")

        if codec != 'h264':
            # If the codec is not h264, convert the file to h264
            file_dir = os.path.dirname(file_path)
            file_name, file_extension = os.path.splitext(os.path.basename(file_path))
            # Use a temporary filename for conversion, then replace the original
            temp_file_path = os.path.join(file_dir, f"temp_x264_{file_name}{file_extension}")
            convert_command = f'ffmpeg -i "{file_path}" -c:v libx264 -c:a aac -strict experimental -b:a 192k "{temp_file_path}"'
            logger.debug(f"Running conversion command: {convert_command}")
            subprocess.run(convert_command, shell=True, check=True)
            logger.debug(f"Conversion successful: {temp_file_path}")
            
            # Replace the original file with the converted one to preserve the filename
            os.remove(file_path)
            os.rename(temp_file_path, file_path)
            
            # Restore the original modification time to maintain file list position
            os.utime(file_path, (original_mtime, original_mtime))
            logger.debug(f"Replaced original file with converted version: {file_path}")
            
            # Update download status to completed if we have a download_id
            if download_id:
                download_manager.update_status(download_id, 'completed', 100, filename=file_path)
        else:
            logger.debug("No conversion needed. The file is already h264.")
            # Update download status to completed if we have a download_id
            if download_id:
                download_manager.update_status(download_id, 'completed', 100, filename=file_path)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error during conversion: {e}")
        # Update download status to failed if we have a download_id
        if download_id:
            download_manager.update_status(download_id, 'failed', error=f"Conversion failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        # Update download status to failed if we have a download_id
        if download_id:
            download_manager.update_status(download_id, 'failed', error=f"Conversion error: {str(e)}")











@app.route('/url_control', methods=['GET', 'POST'])
def url_control():
    url_files = [
        '/mnt/synology/misc/dev/tv_control/url1.txt',
        '/mnt/synology/misc/dev/tv_control/url2.txt',
        '/mnt/synology/misc/dev/tv_control/url3.txt',
        '/mnt/synology/misc/dev/tv_control/url4.txt'
    ]
    
    urls = []
    
    # Load current URLs from files
    for file_path in url_files:
        try:
            with open(file_path, 'r') as f:
                urls.append(f.read().strip())
        except IOError:
            urls.append('')  # If file doesn't exist, append an empty string

    # Create a mapping of URLs to channel names and group channels by category
    url_to_channel = {}
    channels = []
    channels_by_category = {}
    playlist_path = '/mnt/synology/misc/dev/file_share/url_control/playlist.m3u'
    
    # Get last update time for the playlist
    last_update_time = None
    try:
        last_update_time = os.path.getmtime(playlist_path)
    except OSError:
        pass
    
    try:
        with open(playlist_path, 'r') as f:
            lines = f.readlines()
            for i in range(len(lines)):
                if lines[i].startswith('#EXTINF:'):
                    # Parse the EXTINF line to extract group-title
                    extinf_line = lines[i]
                    channel_name = lines[i].split(',', 1)[1].strip()
                    channel_url = lines[i + 1].strip()
                    
                    # Extract group-title from the EXTINF line
                    category = "Other"  # Default category
                    if 'group-title=' in extinf_line:
                        # Find group-title="..." and extract the value
                        import re
                        match = re.search(r'group-title="([^"]*)"', extinf_line)
                        if match:
                            category = match.group(1)
                    
                    # Add to channels list (for backward compatibility)
                    channels.append((channel_name, channel_url))
                    url_to_channel[channel_url] = channel_name
                    
                    # Add to category groups
                    if category not in channels_by_category:
                        channels_by_category[category] = []
                    channels_by_category[category].append((channel_name, channel_url))

    except IOError:
        logger.error(f"Error reading playlist file: {playlist_path}")

    if request.method == 'POST':
        # Check if this is a channel assignment or a full update
        assign_value = request.form.get('assign')
        if assign_value:
            # This is a channel assignment - update only the specified URL
            url_index = int(assign_value) - 1
            new_url = request.form.get(f'url{assign_value}')
            
            # Keep existing URLs, only update the specified one
            for i, file_path in enumerate(url_files):
                try:
                    if i == url_index:
                        # Update the specified URL
                        with open(file_path, 'w') as f:
                            f.write(new_url)
                    else:
                        # Keep the existing URL
                        if urls[i]:  # Only write if there's an existing URL
                            with open(file_path, 'w') as f:
                                f.write(urls[i])
                except IOError as e:
                    logger.error(f"Error saving URL to {file_path}: {e}")
        else:
            # This is a full update from the main form
            for i, file_path in enumerate(url_files):
                new_url = request.form.get(f'url{i+1}', '').strip()
                try:
                    with open(file_path, 'w') as f:
                        f.write(new_url)
                except IOError as e:
                    logger.error(f"Error saving URL to {file_path}: {e}")

        return redirect('https://blandfx.com/files/url_control')

    # Create a list of tuples (index, url) for the template
    indexed_urls = list(enumerate(urls))

    return render_template('url_control.html', indexed_urls=indexed_urls, channels=channels, url_to_channel=url_to_channel, channels_by_category=channels_by_category, last_update_time=last_update_time)

@app.route('/update_channels', methods=['POST'])
def update_channels():
    """Update channels by running api_fetch.py and json_to_m3u.py"""
    try:
        import subprocess
        import os
        
        # Change to the url_control directory
        url_control_dir = '/mnt/synology/misc/dev/file_share/url_control'
        original_dir = os.getcwd()
        
        try:
            os.chdir(url_control_dir)
            
            # Run api_fetch.py to get latest data
            logger.info("Running api_fetch.py to get latest channel data...")
            result = subprocess.run(['python3', 'api_fetch.py'], 
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                logger.error(f"api_fetch.py failed: {result.stderr}")
                return jsonify({'success': False, 'error': f'api_fetch.py failed: {result.stderr}'})
            
            # Find the most recent JSON file
            json_files = [f for f in os.listdir('.') if f.startswith('api_channels_') and f.endswith('.json')]
            if not json_files:
                return jsonify({'success': False, 'error': 'No JSON file found after api_fetch.py'})
            
            # Get the most recent file
            latest_json = max(json_files, key=os.path.getctime)
            logger.info(f"Using JSON file: {latest_json}")
            
            # Run json_to_m3u.py to convert to M3U
            logger.info("Running json_to_m3u.py to convert to M3U...")
            result = subprocess.run(['python3', 'json_to_m3u.py', latest_json, 'playlist.m3u'], 
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                logger.error(f"json_to_m3u.py failed: {result.stderr}")
                return jsonify({'success': False, 'error': f'json_to_m3u.py failed: {result.stderr}'})
            
            logger.info("Channels updated successfully")
            return jsonify({'success': True, 'message': 'Channels updated successfully'})
            
        finally:
            os.chdir(original_dir)
            
    except subprocess.TimeoutExpired:
        logger.error("Update process timed out")
        return jsonify({'success': False, 'error': 'Update process timed out'})
    except Exception as e:
        logger.error(f"Error updating channels: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/cam')
def webcam_stream():
    return render_template('webcam.html')

@app.route('/docs')
def documentation():
    return render_template('docs.html')

@app.template_filter('datetime')
def format_datetime(timestamp):
    if timestamp is None:
        return "Never"
    
    now = datetime.now()
    update_time = datetime.fromtimestamp(timestamp)
    diff = now - update_time
    
    if diff.days > 0:
        if diff.days == 1:
            return "1 day ago"
        else:
            return f"{diff.days} days ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        if hours == 1:
            return "1 hour ago"
        else:
            return f"{hours} hours ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        if minutes == 1:
            return "1 minute ago"
        else:
            return f"{minutes} minutes ago"
    else:
        return "Just now"

@app.route('/blocked_ips')
def view_blocked_ips():
    if 'authenticated' not in session:
        return redirect('https://blandfx.com/files/login')
    
    blocked_ips = load_blocked_ips()
    # Filter out expired blocks
    current_time = time.time()
    active_blocks = {
        ip: block_time for ip, block_time in blocked_ips["blocked_ips"].items()
        if current_time - block_time < INITIAL_BLOCK_DURATION
    }
    return render_template('blocked_ips.html', blocked_ips=active_blocks)

@app.route('/blocked_devices')
def view_blocked_devices():
    if 'authenticated' not in session:
        return redirect('https://blandfx.com/files/login')
    
    # Get all flash messages and filter to only keep device-related ones
    all_messages = get_flashed_messages(with_categories=True)
    device_messages = []
    for category, message in all_messages:
        # Only keep messages related to blocked devices
        message_lower = message.lower()
        if any(keyword in message_lower for keyword in ['device', 'blocked', 'unblock']):
            device_messages.append((category, message))
    
    # Clear all flash messages (they've been consumed)
    # Re-flash only the device-related messages
    for category, message in device_messages:
        flash(message, category)
    
    blocked_devices = load_blocked_devices()
    # Filter out expired blocks
    current_time = time.time()
    active_blocks = {
        device_id: info for device_id, info in blocked_devices["blocked_devices"].items()
        if current_time - info["block_time"] < info["duration"]
    }
    return render_template('blocked_devices.html', blocked_devices=active_blocks)

@app.route('/unblock_device/<device_id>')
def unblock_device(device_id):
    if 'authenticated' not in session:
        return redirect('https://blandfx.com/files/login')
    
    blocked_devices = load_blocked_devices()
    if device_id in blocked_devices["blocked_devices"]:
        del blocked_devices["blocked_devices"][device_id]
        save_blocked_devices(blocked_devices)
        flash(f'Device {device_id} has been unblocked.', 'success')
    else:
        flash(f'Device {device_id} is not blocked.', 'error')
    return redirect('https://blandfx.com/files/blocked_devices')

# Torran (Torrent Search and Download) routes
TORRAN_CONFIG = {
    'JACKETT_URL': 'http://192.168.0.182:9117',
    'JACKETT_API_KEY': 'oilt3apheg4b95hfldvdun7l0l4nqc0h',
    'QBITTORRENT_HOST': 'http://192.168.0.182:8080',
    'QBITTORRENT_USER': 'admin',
    'QBITTORRENT_PASS': 'snake99('
}

# Plex configuration
PLEX_CONFIG = {
    'BASEURL': 'http://192.168.0.87:32400',
    'TOKEN': 'Ss3QsDaCiwXnsXQnj43x'
}

def check_plex_library(title, year, media_type):
    """Check if media exists in Plex library"""
    try:
        from plexapi.server import PlexServer
        plex = PlexServer(PLEX_CONFIG['BASEURL'], PLEX_CONFIG['TOKEN'])
        
        # Format title with year: "Title (Year)"
        search_title = f"{title} ({year})"
        
        # Search in appropriate library type
        if media_type == 'movie':
            results = plex.library.search(title=title, libtype='movie')
        else:  # tv/show
            results = plex.library.search(title=title, libtype='show')
        
        # Check if we found a match with matching year
        for item in results:
            if item.title.lower() == title.lower():
                item_year = item.year if hasattr(item, 'year') and item.year else None
                if item_year == year:
                    return True
        
        return False
    except Exception as e:
        logger.error(f"Error checking Plex library: {e}")
        return False

# Cache for Plex library data
_plex_cache = {
    'data': {},
    'timestamp': 0,
    'cache_duration': 300  # Cache for 5 minutes
}

def get_plex_library_cache():
    """Get cached Plex library data or fetch if cache is expired"""
    import time
    current_time = time.time()
    
    # Return cached data if still valid
    if _plex_cache['data'] and (current_time - _plex_cache['timestamp']) < _plex_cache['cache_duration']:
        return _plex_cache['data']
    
    # Cache expired or empty, fetch fresh data
    try:
        from plexapi.server import PlexServer
        plex = PlexServer(PLEX_CONFIG['BASEURL'], PLEX_CONFIG['TOKEN'])
        
        plex_movies = {}
        plex_shows = {}
        
        logger.debug("Fetching Plex library data for cache...")
        for section in plex.library.sections():
            if section.type == 'movie':
                for item in section.all():
                    title_key = f"{item.title.lower()}_{item.year if hasattr(item, 'year') and item.year else None}"
                    plex_movies[title_key] = True
            elif section.type == 'show':
                for item in section.all():
                    title_key = f"{item.title.lower()}_{item.year if hasattr(item, 'year') and item.year else None}"
                    plex_shows[title_key] = True
        
        cache_data = {
            'movies': plex_movies,
            'shows': plex_shows
        }
        
        # Update cache
        _plex_cache['data'] = cache_data
        _plex_cache['timestamp'] = current_time
        
        logger.debug(f"Plex cache updated. Movies: {len(plex_movies)}, Shows: {len(plex_shows)}")
        return cache_data
        
    except Exception as e:
        logger.error(f"Error fetching Plex library cache: {e}")
        # Return empty cache on error
        return {'movies': {}, 'shows': {}}

def check_multiple_plex_items(items):
    """Check multiple items in Plex library efficiently using cache"""
    try:
        # Get cached Plex data (or fetch if needed)
        plex_data = get_plex_library_cache()
        plex_movies = plex_data.get('movies', {})
        plex_shows = plex_data.get('shows', {})
        
        results = {}
        
        # Check each item against cached data
        for item in items:
            title = item.get('name', '').lower()
            year = item.get('year')
            media_type = item.get('media_type', '')
            
            title_key = f"{title}_{year}"
            
            if media_type == 'movie':
                results[item.get('tmdb_id')] = title_key in plex_movies
            else:  # tv/show
                results[item.get('tmdb_id')] = title_key in plex_shows
        
        return results
    except Exception as e:
        logger.error(f"Error checking multiple Plex items: {e}")
        return {}

def load_tmdb_credentials():
    """Load TMDB credentials from tmdb.creds file"""
    creds_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tmdb.creds')
    credentials = {}
    try:
        with open(creds_file, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    credentials[key.strip()] = value.strip()
        return credentials
    except FileNotFoundError:
        logger.error(f"TMDB credentials file not found: {creds_file}")
        return {}

def get_tv_show_details(tv_id):
    """Get TV show details including number of seasons"""
    credentials = load_tmdb_credentials()
    access_token = credentials.get('ACCESS_TOKEN')
    
    if not access_token:
        return None
    
    url = f"https://api.themoviedb.org/3/tv/{tv_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "accept": "application/json"
    }
    params = {
        "language": "en-US"
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        # Return number of seasons
        return data.get('number_of_seasons', None)
    except requests.exceptions.RequestException as e:
        logger.debug(f"Error fetching TV show details for {tv_id}: {e}")
        return None

def get_top_cast(media_id, media_type):
    """Get top 2 cast members for a movie or TV show"""
    credentials = load_tmdb_credentials()
    access_token = credentials.get('ACCESS_TOKEN')
    
    if not access_token:
        return []
    
    # Use credits endpoint for both movies and TV shows
    endpoint = 'movie' if media_type == 'movie' else 'tv'
    url = f"https://api.themoviedb.org/3/{endpoint}/{media_id}/credits"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "accept": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Get cast list (already sorted by order)
        cast = data.get('cast', [])
        
        # Return top 2 cast members' names
        top_cast = []
        for actor in cast[:2]:
            if actor.get('name'):
                top_cast.append(actor['name'])
        
        return top_cast
    except requests.exceptions.RequestException as e:
        logger.debug(f"Error fetching cast for {media_type} {media_id}: {e}")
        return []

def search_tmdb(query):
    """Search The Movie Database API"""
    credentials = load_tmdb_credentials()
    access_token = credentials.get('ACCESS_TOKEN')
    
    if not access_token:
        logger.error("TMDB access token not found")
        return None
    
    url = "https://api.themoviedb.org/3/search/multi"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "accept": "application/json"
    }
    params = {
        "query": query,
        "include_adult": "false",
        "language": "en-US",
        "page": 1
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error searching TMDB: {e}")
        return None

def search_jackett(query):
    """Search Jackett for torrents"""
    url = f"{TORRAN_CONFIG['JACKETT_URL']}/api/v2.0/indexers/iptorrents/results"
    params = {
        "apikey": TORRAN_CONFIG['JACKETT_API_KEY'],
        "Query": query
    }
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error searching Jackett: {e}")
        return None

@app.route('/torran', methods=['GET', 'POST'])
def torran():
    if 'authenticated' not in session:
        return redirect('https://blandfx.com/files/login')
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'search_tmdb':
            # Handle TMDB search request
            search_query = request.form.get('query', '').strip()
            if not search_query:
                return jsonify({'success': False, 'error': 'Search query is required'})
            
            tmdb_results = search_tmdb(search_query)
            if not tmdb_results or not tmdb_results.get('results'):
                return jsonify({'success': False, 'error': 'No results found'})
            
            # Format and filter results (only movies and TV shows)
            formatted_results = []
            query_lower = search_query.lower().strip()
            
            for result in tmdb_results['results']:
                media_type = result.get('media_type')
                if media_type not in ['movie', 'tv']:
                    continue
                
                # Get name (title for movies, name for TV shows)
                name = result.get('title') or result.get('name', '')
                
                # Get release/air date
                release_date = result.get('release_date') or result.get('first_air_date', '')
                year = release_date.split('-')[0] if release_date else None
                
                if not name or not year:
                    continue
                
                # Calculate custom relevance score
                name_lower = name.lower().strip()
                
                # 1. Exact title match bonus (highest weight)
                exact_match_bonus = 100 if name_lower == query_lower else 0
                
                # 2. Add log-based vote count (to prevent massive counts from overpowering everything)
                vote_count = result.get('vote_count', 0)
                vote_score = vote_count * 0.1
                
                # 3. Add raw popularity
                popularity = result.get('popularity', 0)
                
                # Calculate total custom score
                custom_score = exact_match_bonus + vote_score + popularity
                
                # Get number of seasons for TV shows
                num_seasons = None
                if media_type == 'tv':
                    tv_id = result.get('id')
                    if tv_id:
                        num_seasons = get_tv_show_details(tv_id)
                
                # Get top 2 cast members
                top_cast = []
                media_id = result.get('id')
                if media_id:
                    top_cast = get_top_cast(media_id, media_type)
                
                formatted_results.append({
                    'name': name,
                    'type': 'Movie' if media_type == 'movie' else 'Series',
                    'year': int(year),
                    'release_date': release_date,
                    'tmdb_id': result.get('id'),
                    'media_type': media_type,
                    'popularity': popularity,
                    'vote_count': vote_count,
                    'custom_score': custom_score,
                    'num_seasons': num_seasons,
                    'top_cast': top_cast
                })
            
            # Sort by custom relevance score (descending)
            formatted_results.sort(key=lambda x: x['custom_score'], reverse=True)
            
            # Return results immediately without Plex check (will be added async via JavaScript)
            return jsonify({'success': True, 'results': formatted_results})
        
        elif action == 'search':
            # Handle Torran/Jackett search request (after TMDB selection)
            search_query = request.form.get('query', '').strip()
            if not search_query:
                return jsonify({'success': False, 'error': 'Search query is required'})
            
            results = search_jackett(search_query)
            if not results or not results.get('Results'):
                return jsonify({'success': False, 'error': 'No results found'})
            
            # Filter and sort results (prioritize 265, sort by grabs/seeders)
            results_265 = [r for r in results['Results'] if '265' in r['Title']]
            other_results = [r for r in results['Results'] if '265' not in r['Title']]
            sorted_265 = sorted(results_265, key=lambda x: x.get('Grabs', x.get('Seeders', 0)), reverse=True)
            sorted_other = sorted(other_results, key=lambda x: x.get('Grabs', x.get('Seeders', 0)), reverse=True)
            combined_results = sorted_265 + sorted_other
            top_results = combined_results[:5]
            
            # Format results for display
            formatted_results = []
            for i, result in enumerate(top_results):
                size_gb = result['Size'] / (1024**3)
                
                # Format publish date
                pub_date = result.get('PublishDate')
                formatted_date = 'N/A'
                if pub_date:
                    try:
                        # Jackett typically returns ISO format like "2024-05-20T12:00:00"
                        if 'T' in pub_date:
                            formatted_date = pub_date.split('T')[0]
                        else:
                            formatted_date = str(pub_date)
                    except Exception:
                        formatted_date = str(pub_date)

                formatted_results.append({
                    'index': i,
                    'title': result['Title'],
                    'size_gb': f"{size_gb:.2f}",
                    'grabs': result.get('Grabs', 'N/A'),
                    'seeders': result.get('Seeders', 'N/A'),
                    'publish_date': formatted_date,
                    'magnet_uri': result.get('MagnetUri') or result.get('Link', ''),
                    'infohash': result.get('InfoHash', '')
                })
            
            return jsonify({'success': True, 'results': formatted_results})
        
        elif action == 'add_torrent':
            # Handle adding torrent to qBittorrent
            torrent_index = request.form.get('torrent_index')
            category = request.form.get('category')
            magnet_uri = request.form.get('magnet_uri')
            torrent_url = request.form.get('torrent_url')
            
            if not category:
                return jsonify({'success': False, 'error': 'Category is required'})
            
            if category not in ['movies', 'shows', 'kid_movies', 'kid_shows']:
                return jsonify({'success': False, 'error': 'Invalid category'})
            
            try:
                import qbittorrentapi
                qbt_client = qbittorrentapi.Client(
                    host=TORRAN_CONFIG['QBITTORRENT_HOST'],
                    username=TORRAN_CONFIG['QBITTORRENT_USER'],
                    password=TORRAN_CONFIG['QBITTORRENT_PASS']
                )
                qbt_client.auth_log_in()
                
                # Add torrent - magnet_uri can be either a magnet link or HTTP URL
                torrent_url_to_add = magnet_uri or torrent_url
                if not torrent_url_to_add:
                    return jsonify({'success': False, 'error': 'No torrent URL or magnet URI provided'})
                
                # If it's an HTTP URL (not magnet), download the torrent file first
                if torrent_url_to_add.startswith('http') and not torrent_url_to_add.startswith('magnet:'):
                    # Download torrent file first
                    torrent_response = requests.get(torrent_url_to_add, timeout=30)
                    torrent_response.raise_for_status()
                    import tempfile
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.torrent') as tmp_file:
                        tmp_file.write(torrent_response.content)
                        tmp_file_path = tmp_file.name
                    
                    try:
                        with open(tmp_file_path, 'rb') as f:
                            qbt_client.torrents_add(torrent_files=f, category=category)
                    finally:
                        os.unlink(tmp_file_path)
                else:
                    # It's a magnet link
                    qbt_client.torrents_add(urls=[torrent_url_to_add], category=category)
                
                return jsonify({'success': True, 'message': f'Torrent added to qBittorrent in category: {category}'})
                
            except qbittorrentapi.exceptions.LoginFailed as e:
                logger.error(f"qBittorrent login failed: {e}")
                return jsonify({'success': False, 'error': f'qBittorrent login failed: {str(e)}'})
            except Exception as e:
                logger.error(f"Error adding torrent: {e}")
                return jsonify({'success': False, 'error': f'Error adding torrent: {str(e)}'})
    
    # GET request - show the search interface
    # Pre-fetch Plex library data in background thread (non-blocking)
    def refresh_plex_cache_background():
        try:
            get_plex_library_cache()  # This will cache the data
            logger.debug("Plex cache refreshed in background")
        except Exception as e:
            logger.error(f"Error pre-fetching Plex cache: {e}")
    
    # Start background thread for Plex cache refresh
    thread = threading.Thread(target=refresh_plex_cache_background, daemon=True)
    thread.start()
    
    return render_template('torran.html')

@app.route('/torran/check_plex', methods=['POST'])
def check_plex_status():
    """Check Plex status for multiple items (async endpoint)"""
    if 'authenticated' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        items = data.get('items', [])
        
        if not items:
            return jsonify({'success': False, 'error': 'No items provided'})
        
        # Check Plex status using cached data
        plex_status = check_multiple_plex_items(items)
        
        return jsonify({'success': True, 'plex_status': plex_status})
    except Exception as e:
        logger.error(f"Error checking Plex status: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/torran/refresh_plex_cache', methods=['POST'])
def refresh_plex_cache():
    """Manually refresh the Plex cache"""
    if 'authenticated' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    try:
        # Clear cache to force refresh
        _plex_cache['data'] = {}
        _plex_cache['timestamp'] = 0
        
        # Fetch fresh data
        get_plex_library_cache()
        
        return jsonify({'success': True, 'message': 'Plex cache refreshed'})
    except Exception as e:
        logger.error(f"Error refreshing Plex cache: {e}")
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5578)
