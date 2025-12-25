# app.py
#!/usr/bin/env python3
"""
Device Incident Analyzer - Web Application
Flask-based web interface for analyzing security incidents by device
With FortiSIEM vendor lookup integration
+ Live GUI: XML query + progress + results via SSE (Server-Sent Events)
"""

from flask import Flask, render_template, jsonify, request, send_file, Response, stream_with_context
import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import json
import csv
import io
import requests
from requests.auth import HTTPBasicAuth
import xml.etree.ElementTree as ET
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import pandas as pd
import os
from pathlib import Path
import re

# Load environment variables
load_dotenv()

# Configure comprehensive logging for debug
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app_debug.log')
    ]
)
logger = logging.getLogger(__name__)

# Enable debug mode from environment
DEBUG_MODE = os.getenv('DEBUG_MODE', 'true').lower() == 'true'  # Default to true for comprehensive logging
if DEBUG_MODE:
    logger.setLevel(logging.DEBUG)
    logger.info("=== DEBUG MODE ENABLED - Comprehensive logging active ===")
else:
    logger.info("=== PRODUCTION MODE - Standard logging active ===")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Request/Response logging middleware
@app.before_request
def log_request_info():
    """Log detailed information about incoming requests"""
    request_id = id(request)  # Simple request ID for tracking

    logger.info(f"REQUEST START [ID: {request_id}] {request.method} {request.path}")
    logger.debug(f"Request details [ID: {request_id}]:")
    logger.debug(f"  - Remote Address: {request.remote_addr}")
    logger.debug(f"  - User Agent: {request.headers.get('User-Agent', 'Unknown')}")
    logger.debug(f"  - Content Type: {request.headers.get('Content-Type', 'None')}")

    if request.args:
        logger.debug(f"  - Query Parameters: {dict(request.args)}")

    if request.method in ['POST', 'PUT', 'PATCH'] and request.is_json:
        logger.debug(f"  - JSON Body: {request.get_json()}")

    request.start_time = time.time()
    request.request_id = request_id

@app.after_request
def log_response_info(response):
    """Log detailed information about outgoing responses"""
    request_id = getattr(request, 'request_id', 'Unknown')
    start_time = getattr(request, 'start_time', time.time())
    duration = (time.time() - start_time) * 1000  # ms

    logger.info(f"REQUEST END [ID: {request_id}] {request.method} {request.path} - Status: {response.status_code} - Duration: {duration:.2f}ms")
    logger.debug(f"Response details [ID: {request_id}]:")
    logger.debug(f"  - Status: {response.status} ({response.status_code})")
    logger.debug(f"  - Content Type: {response.headers.get('Content-Type', 'Unknown')}")
    logger.debug(f"  - Content Length: {response.headers.get('Content-Length', 'Unknown')} bytes")

    if response.is_json and response.status_code < 500:
        try:
            response_data = response.get_json()
            response_str = str(response_data)
            if len(response_str) > 1000:
                logger.debug(f"  - Response Body (truncated): {response_str[:1000]}...")
            else:
                logger.debug(f"  - Response Body: {response_data}")
        except Exception:
            logger.debug("  - Response Body: (Unable to parse JSON)")

    return response

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'port': int(os.getenv('DB_PORT', 3306))
}

# FortiSIEM Configuration
FORTISIEM_CONFIG = {
    'ip': os.getenv('FORTISIEM_IP', 'soc.techowl.in'),
    'username': os.getenv('FORTISIEM_USER', 'super/admin'),
    # IMPORTANT: do NOT hardcode password in code. keep in .env
    'password': os.getenv('FORTISIEM_PASSWORD', ''),
    'verify_ssl': os.getenv('FORTISIEM_VERIFY_SSL', 'false').lower() == 'true'
}

# Cache for vendor info (to avoid repeated queries)
vendor_cache = {}
vendor_cache_lock = threading.Lock()

# Excel file paths for data storage
VENDOR_SELECTIONS_FILE = 'data/vendor_selections.xlsx'
VENDOR_INCIDENTS_FILE = 'data/vendor_incidents.xlsx'
VENDOR_RULES_FILE = 'data/vendor_rules.xlsx'

# Ensure data directory exists
Path('data').mkdir(exist_ok=True)

# Cache for rules data
rules_cache = {}
rules_cache_lock = threading.Lock()


def load_vendor_selections():
    """Load vendor selections from Excel file"""
    try:
        if os.path.exists(VENDOR_SELECTIONS_FILE):
            df = pd.read_excel(VENDOR_SELECTIONS_FILE)
            return df
        else:
            # Create empty DataFrame with required columns
            df = pd.DataFrame(columns=[
                'client_id', 'device_name', 'selected_vendor', 'selected_model', 
                'created_at', 'updated_at'
            ])
            return df
    except Exception as e:
        logger.error(f"Error loading vendor selections: {e}")
        # Return empty DataFrame on error
        return pd.DataFrame(columns=[
            'client_id', 'device_name', 'selected_vendor', 'selected_model', 
            'created_at', 'updated_at'
        ])


def save_vendor_selections(df):
    """Save vendor selections to Excel file"""
    try:
        df.to_excel(VENDOR_SELECTIONS_FILE, index=False)
        logger.info(f"Vendor selections saved to {VENDOR_SELECTIONS_FILE}")
        return True
    except Exception as e:
        logger.error(f"Error saving vendor selections: {e}")
        return False


def get_vendor_selection(client_id, device_name):
    """Get vendor selection for a specific client and device"""
    df = load_vendor_selections()
    selection = df[(df['client_id'] == client_id) & (df['device_name'] == device_name)]
    if not selection.empty:
        return selection.iloc[0].to_dict()
    return None


def save_vendor_selection(client_id, device_name, vendor, model):
    """Save or update vendor selection for a device"""
    try:
        df = load_vendor_selections()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Check if selection already exists
        mask = (df['client_id'] == client_id) & (df['device_name'] == device_name)
        
        if mask.any():
            # Update existing selection
            df.loc[mask, 'selected_vendor'] = vendor
            df.loc[mask, 'selected_model'] = model
            df.loc[mask, 'updated_at'] = now
        else:
            # Add new selection
            new_row = {
                'client_id': client_id,
                'device_name': device_name,
                'selected_vendor': vendor,
                'selected_model': model,
                'created_at': now,
                'updated_at': now
            }
            df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
        
        return save_vendor_selections(df)
    except Exception as e:
        logger.error(f"Error saving vendor selection: {e}")
        return False


def get_client_vendor_selections(client_id):
    """Get all vendor selections for a client"""
    df = load_vendor_selections()
    selections = df[df['client_id'] == client_id]
    return selections.to_dict('records') if not selections.empty else []


def fetch_fortisiem_rules():
    """Fetch rules data from FortiSIEM API"""
    logger.info("Fetching rules data from FortiSIEM API")
    
    if not FORTISIEM_CONFIG['password']:
        logger.error("FORTISIEM_PASSWORD is empty. Cannot fetch rules.")
        return None
    
    try:
        url = f"https://{FORTISIEM_CONFIG['ip']}/phoenix/rest/dataRequest/rule"
        auth = HTTPBasicAuth(FORTISIEM_CONFIG['username'], FORTISIEM_CONFIG['password'])
        
        response = requests.get(
            url,
            auth=auth,
            verify=FORTISIEM_CONFIG['verify_ssl'],
            timeout=60
        )
        
        if response.status_code == 200:
            logger.info("Successfully fetched rules data from FortiSIEM")
            return response.text
        else:
            logger.error(f"Failed to fetch rules from FortiSIEM: HTTP {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching rules from FortiSIEM: {e}")
        return None


def parse_rules_xml(xml_content):
    """Parse XML content and extract vendor-rule mappings"""
    logger.info("Parsing rules XML content")
    
    if not xml_content:
        return {}
    
    try:
        # Parse XML
        root = ET.fromstring(xml_content)
        vendor_rules = {}
        
        # Find all DataRequest elements (rules)
        for data_request in root.findall('DataRequest'):
            rule_id = data_request.get('id', '')
            rule_name_elem = data_request.find('Name')
            data_source_elem = data_request.find('DataSource')
            function_elem = data_request.get('function', '')
            incident_category = data_request.get('phIncidentCategory', '')
            
            if rule_name_elem is not None and data_source_elem is not None:
                rule_name = rule_name_elem.text or ''
                data_source = data_source_elem.text or ''
                
                # Extract vendors from data source using regex patterns
                vendors = extract_vendors_from_datasource(data_source)
                
                rule_info = {
                    'id': rule_id,
                    'name': rule_name,
                    'data_source': data_source,
                    'function': function_elem,
                    'category': incident_category,
                    'vendors': vendors
                }
                
                # Map each vendor to this rule
                for vendor in vendors:
                    if vendor not in vendor_rules:
                        vendor_rules[vendor] = []
                    vendor_rules[vendor].append(rule_info)
        
        logger.info(f"Parsed {len([rule for rules in vendor_rules.values() for rule in rules])} rules for {len(vendor_rules)} vendors")
        return vendor_rules
        
    except ET.ParseError as e:
        logger.error(f"Error parsing rules XML: {e}")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error parsing rules: {e}")
        return {}


def extract_vendors_from_datasource(data_source):
    """Extract vendor names from data source string"""
    vendors = set()
    
    if not data_source:
        return list(vendors)
    
    # Common vendor patterns in data sources
    vendor_patterns = {
        'Fortigate': ['fortigate', 'fortiguard'],
        'FortiEDR': ['fortiedr'],
        'FortiDeceptor': ['fortideceptor'],
        'FortiAnalyzer': ['fortianalyzer'],
        'FortiWeb': ['fortiweb'],
        'FortiRecon': ['fortirecon'],
        'Microsoft': ['microsoft', 'windows'],
        'Cisco': ['cisco'],
        'Palo Alto': ['palo alto', 'paloalto'],
        'Checkpoint': ['checkpoint', 'check point'],
        'F5': ['f5'],
        'TrendMicro': ['trendmicro', 'trend micro'],
        'Symantec': ['symantec'],
        'McAfee': ['mcafee'],
        'HP': ['hp'],
        'Dell': ['dell'],
        'VMware': ['vmware'],
        'Linux': ['linux'],
        'Apache': ['apache'],
        'Nginx': ['nginx'],
        'Oracle': ['oracle'],
        'MySQL': ['mysql'],
        'PostgreSQL': ['postgresql'],
        'MongoDB': ['mongodb']
    }
    
    data_source_lower = data_source.lower()
    
    for vendor, patterns in vendor_patterns.items():
        for pattern in patterns:
            if pattern in data_source_lower:
                vendors.add(vendor)
                break
    
    # If no specific vendor found, try to extract from common formats
    if not vendors:
        # Try to extract vendor from formats like "VendorName via Syslog"
        via_pattern = r'(\w+)\s+via\s+'
        matches = re.findall(via_pattern, data_source, re.IGNORECASE)
        for match in matches:
            if len(match) > 2:  # Avoid short matches
                vendors.add(match.title())
    
    return list(vendors) if vendors else ['Unknown']


def load_rules_data(force_refresh=False):
    """Load rules data from cache or fetch from FortiSIEM"""
    with rules_cache_lock:
        if not force_refresh and rules_cache:
            logger.debug("Using cached rules data")
            return rules_cache
        
        logger.info("Loading fresh rules data from FortiSIEM")
        xml_content = fetch_fortisiem_rules()
        
        if xml_content:
            vendor_rules = parse_rules_xml(xml_content)
            rules_cache.update(vendor_rules)
            logger.info(f"Loaded rules for {len(vendor_rules)} vendors into cache")
            return rules_cache
        else:
            logger.warning("Failed to fetch rules data, returning empty cache")
            return rules_cache


def get_rules_for_vendors(vendor_list):
    """Get all rules applicable to the given list of vendors"""
    if not vendor_list:
        return {}
    
    rules_data = load_rules_data()
    vendor_rules = {}
    
    for vendor in vendor_list:
        # Try exact match first
        if vendor in rules_data:
            vendor_rules[vendor] = rules_data[vendor]
        else:
            # Try fuzzy matching
            for cached_vendor in rules_data.keys():
                if vendor.lower() in cached_vendor.lower() or cached_vendor.lower() in vendor.lower():
                    if vendor not in vendor_rules:
                        vendor_rules[vendor] = []
                    vendor_rules[vendor].extend(rules_data[cached_vendor])
    
    return vendor_rules


def get_db_connection():
    """Establish database connection"""
    logger.debug(f"Attempting DB connection: host={DB_CONFIG['host']} user={DB_CONFIG['user']} db={DB_CONFIG['database']} port={DB_CONFIG['port']}")
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        logger.info("Database connection established successfully")
        return conn
    except Error as e:
        logger.error(f"Database connection failed: {e}")
        return None


def _escape_for_xml_attr(value: str) -> str:
    """Escape string for safe use inside XML attribute values."""
    if value is None:
        return ''
    # IMPORTANT: escape & first
    return (value.replace("&", "&amp;")
                 .replace('"', "&quot;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;"))


def build_vendor_lookup_xml(device_name: str, client_id: int, low_time: int, high_time: int) -> str:
    """Build FortiSIEM XML query for vendor/model lookup grouped by vendor+model."""
    escaped_device_name = _escape_for_xml_attr(device_name)
    xml_query = f'''<?xml version="1.0" encoding="UTF-8"?>
<Reports>
    <Report>
        <DataSource/>
        <Name>Device Vendor Lookup - {escaped_device_name}</Name>
        <Description>Vendor lookup query for device reports from FortiSIEM</Description>
        <PatternClause>
            <SubPattern id="1" name="">
                <SingleEvtConstr>reptDevName="{escaped_device_name}" AND phCustId={client_id}</SingleEvtConstr>
                <GroupByAttr>reptVendor,reptModel</GroupByAttr>
            </SubPattern>
        </PatternClause>
        <SelectClause>
            <AttrList>reptVendor,reptModel,COUNT(*)</AttrList>
            <ColumnNames>phRecvTime</ColumnNames>
        </SelectClause>
        <OrderByClause>
            <AttrList>COUNT(*) DESC</AttrList>
        </OrderByClause>
        <ReportInterval>
            <Low>{low_time}</Low>
            <High>{high_time}</High>
        </ReportInterval>
    </Report>
</Reports>'''
    return xml_query


def query_fortisiem_vendor(device_name, client_id):
    """
    Query FortiSIEM to get vendor and model for a specific device.

    Returns dict:
      {
        'vendors': [{'vendor':..., 'model':..., 'count':...}, ...],
        'total_entries': N,
        'debug_info': {...} (only in DEBUG_MODE)
      }
    """
    debug_info = {
        'device_name': device_name,
        'client_id': client_id,
        'cache_hit': False,
        'xml_query': None,
        'response_status': None,
        'xml_response': None,
        'parsed_vendors': [],
        'errors': []
    }

    cache_key = f"{client_id}:{device_name}"
    with vendor_cache_lock:
        if cache_key in vendor_cache:
            debug_info['cache_hit'] = True
            cached = vendor_cache[cache_key].copy()
            if DEBUG_MODE:
                cached['debug_info'] = debug_info
            return cached

    if not FORTISIEM_CONFIG['password']:
        msg = "FORTISIEM_PASSWORD is empty. Set it in .env"
        debug_info['errors'].append(msg)
        logger.error(msg)
        if DEBUG_MODE:
            return {'vendors': [{'vendor': 'Error', 'model': 'MissingPassword', 'count': 0}], 'total_entries': 1, 'debug_info': debug_info}
        return None

    base_url = f"https://{FORTISIEM_CONFIG['ip']}/phoenix/rest/query"
    event_query_url = f"{base_url}/eventQuery"

    now = datetime.now(timezone.utc)
    high_time = int(now.timestamp())
    low_time = int((now - timedelta(hours=24)).timestamp())

    xml_query = build_vendor_lookup_xml(device_name, client_id, low_time, high_time)
    debug_info['xml_query'] = xml_query

    try:
        headers = {'Content-Type': 'text/xml'}
        auth = HTTPBasicAuth(FORTISIEM_CONFIG['username'], FORTISIEM_CONFIG['password'])

        response = requests.post(
            event_query_url,
            data=xml_query,
            auth=auth,
            headers=headers,
            verify=FORTISIEM_CONFIG['verify_ssl'],
            timeout=30
        )

        debug_info['response_status'] = response.status_code
        debug_info['xml_response'] = response.text

        if response.status_code != 200:
            msg = f"FortiSIEM submit failed: {response.status_code}"
            debug_info['errors'].append(msg)
            logger.error(msg)
            return None

        root = ET.fromstring(response.text)
        request_id = root.attrib.get('requestId')
        expire_time_elem = root.find('.//expireTime')
        if not request_id or expire_time_elem is None:
            msg = "Invalid FortiSIEM submit response - missing requestId/expireTime"
            debug_info['errors'].append(msg)
            logger.error(msg)
            return None

        expire_time = expire_time_elem.text

        # poll progress
        progress_url = f"{base_url}/progress/{request_id},{expire_time}"
        max_wait = 60
        start_time = time.time()
        progress = 0

        while time.time() - start_time < max_wait and progress < 100:
            pr = requests.get(progress_url, auth=auth, verify=FORTISIEM_CONFIG['verify_ssl'], timeout=10)
            if pr.status_code == 200:
                pr_root = ET.fromstring(pr.text)
                p_elem = pr_root.find('.//progress')
                if p_elem is not None:
                    try:
                        progress = int(p_elem.text)
                    except Exception:
                        pass
                    if progress >= 100:
                        break
            time.sleep(2)

        # fetch results
        fetch_url = f"{base_url}/events/{request_id},{expire_time}/0/100"
        fetch_response = requests.get(fetch_url, auth=auth, verify=FORTISIEM_CONFIG['verify_ssl'], timeout=30)

        if fetch_response.status_code != 200:
            msg = f"FortiSIEM fetch failed: {fetch_response.status_code}"
            debug_info['errors'].append(msg)
            logger.error(msg)
            return None

        results_root = ET.fromstring(fetch_response.text)
        vendors_found = []

        for event in results_root.findall('.//event'):
            attributes = event.find('attributes')
            if attributes is None:
                continue

            vendor = None
            model = None
            count = 1

            for attr in attributes:
                name = attr.attrib.get('name', '')
                if name == 'reptVendor' and attr.text:
                    vendor = attr.text.strip()
                elif name == 'reptModel' and attr.text:
                    model = attr.text.strip()
                elif name == 'COUNT(*)' and attr.text:
                    try:
                        count = int(attr.text)
                    except ValueError:
                        count = 1

            if vendor or model:
                entry = {'vendor': vendor or 'Unknown', 'model': model or 'Unknown', 'count': count}
                vendors_found.append(entry)
                debug_info['parsed_vendors'].append(entry)

        vendors_found.sort(key=lambda x: x['count'], reverse=True)

        # unique
        unique_vendors = []
        seen = set()
        for v in vendors_found:
            key = f"{v['vendor']}:{v['model']}"
            if key not in seen:
                unique_vendors.append(v)
                seen.add(key)

        if not unique_vendors:
            unique_vendors = [{'vendor': 'Unknown', 'model': 'Unknown', 'count': 0}]
            debug_info['parsed_vendors'] = unique_vendors

        # NEW: Auto-save single results
        result = {
            'vendors': unique_vendors, 
            'total_entries': len(unique_vendors),
            'single_result': len(unique_vendors) == 1 and unique_vendors[0]['vendor'] != 'Unknown'
        }
        if DEBUG_MODE:
            result['debug_info'] = debug_info

        with vendor_cache_lock:
            vendor_cache[cache_key] = result

        return result

    except requests.exceptions.RequestException as e:
        msg = f"FortiSIEM request error: {e}"
        debug_info['errors'].append(msg)
        logger.error(msg)
        if DEBUG_MODE:
            return {'vendors': [{'vendor': 'Error', 'model': 'RequestException', 'count': 0}], 'total_entries': 1, 'debug_info': debug_info}
        return None
    except ET.ParseError as e:
        msg = f"FortiSIEM XML parse error: {e}"
        debug_info['errors'].append(msg)
        logger.error(msg)
        if DEBUG_MODE:
            return {'vendors': [{'vendor': 'Error', 'model': 'ParseError', 'count': 0}], 'total_entries': 1, 'debug_info': debug_info}
        return None
    except Exception as e:
        msg = f"Unexpected error: {e}"
        debug_info['errors'].append(msg)
        logger.error(msg)
        if DEBUG_MODE:
            return {'vendors': [{'vendor': 'Error', 'model': 'Unexpected', 'count': 0}], 'total_entries': 1, 'debug_info': debug_info}
        return None


def get_fortisiem_cust_id(client_id):
    """
    Map internal client_id to FortiSIEM phCustId.
    Uses client_details.fs_client_id if present else fallback to client_id.
    """
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT fs_client_id FROM client_details WHERE client_id LIKE %s", (f'%{client_id}%',))
            result = cursor.fetchone()
            if result and result.get('fs_client_id'):
                return int(result['fs_client_id'])
        except Error as e:
            logger.warning(f"Error querying fs_client_id: {e}")
        finally:
            cursor.close()
            conn.close()

    return int(client_id)


# ---------------------------
# NEW: SSE endpoint
# ---------------------------
@app.route('/api/device/vendor/stream')
def stream_device_vendor():
    """
    Stream XML query + submit meta + progress + result for a single device.
    GUI consumes via EventSource and shows:
      - XML query
      - requestId/expireTime
      - progress %
      - parsed vendor/model/count
      - raw result XML
    """
    device_name = request.args.get('device_name')
    cust_id = request.args.get('cust_id')

    if not device_name or not cust_id:
        return jsonify({'error': 'Missing device_name or cust_id'}), 400

    try:
        cust_id = int(cust_id)
    except ValueError:
        return jsonify({'error': 'Invalid cust_id'}), 400

    def sse(event: str, payload: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(payload)}\n\n"

    @stream_with_context
    def generate():
        if not FORTISIEM_CONFIG['password']:
            yield sse("error", {"message": "FORTISIEM_PASSWORD is empty. Set it in .env"})
            return

        base_url = f"https://{FORTISIEM_CONFIG['ip']}/phoenix/rest/query"
        event_query_url = f"{base_url}/eventQuery"

        now = datetime.now(timezone.utc)
        high_time = int(now.timestamp())
        low_time = int((now - timedelta(hours=24)).timestamp())

        xml_query = build_vendor_lookup_xml(device_name, cust_id, low_time, high_time)
        yield sse("xml", {"device_name": device_name, "xml_query": xml_query})

        headers = {'Content-Type': 'text/xml'}
        auth = HTTPBasicAuth(FORTISIEM_CONFIG['username'], FORTISIEM_CONFIG['password'])

        try:
            # submit
            resp = requests.post(
                event_query_url,
                data=xml_query,
                auth=auth,
                headers=headers,
                verify=FORTISIEM_CONFIG['verify_ssl'],
                timeout=30
            )
            yield sse("submit", {"status_code": resp.status_code})

            if resp.status_code != 200:
                yield sse("error", {"message": f"Submit failed: {resp.status_code}", "body": resp.text})
                return

            root = ET.fromstring(resp.text)
            request_id = root.attrib.get('requestId')
            expire_time_elem = root.find('.//expireTime')

            if not request_id or expire_time_elem is None:
                yield sse("error", {"message": "Missing requestId/expireTime in submit response", "body": resp.text})
                return

            expire_time = expire_time_elem.text
            yield sse("meta", {"request_id": request_id, "expire_time": expire_time})

            # progress polling
            progress_url = f"{base_url}/progress/{request_id},{expire_time}"
            max_wait = 60
            start = time.time()
            progress = 0

            while time.time() - start < max_wait and progress < 100:
                pr = requests.get(progress_url, auth=auth, verify=FORTISIEM_CONFIG['verify_ssl'], timeout=10)
                if pr.status_code == 200:
                    pr_root = ET.fromstring(pr.text)
                    p_elem = pr_root.find('.//progress')
                    if p_elem is not None:
                        try:
                            progress = int(p_elem.text)
                        except Exception:
                            pass
                        yield sse("progress", {"progress": progress})
                        if progress >= 100:
                            break
                time.sleep(2)

            # fetch
            fetch_url = f"{base_url}/events/{request_id},{expire_time}/0/100"
            fr = requests.get(fetch_url, auth=auth, verify=FORTISIEM_CONFIG['verify_ssl'], timeout=30)

            if fr.status_code != 200:
                yield sse("error", {"message": f"Fetch failed: {fr.status_code}", "body": fr.text})
                return

            results_root = ET.fromstring(fr.text)
            vendors_found = []
            for event in results_root.findall('.//event'):
                attributes = event.find('attributes')
                if attributes is None:
                    continue

                vendor = None
                model = None
                count = 1

                for attr in attributes:
                    name = attr.attrib.get('name', '')
                    if name == 'reptVendor' and attr.text:
                        vendor = attr.text.strip()
                    elif name == 'reptModel' and attr.text:
                        model = attr.text.strip()
                    elif name == 'COUNT(*)' and attr.text:
                        try:
                            count = int(attr.text)
                        except Exception:
                            count = 1

                if vendor or model:
                    vendors_found.append({
                        "vendor": vendor or "Unknown",
                        "model": model or "Unknown",
                        "count": count
                    })

            vendors_found.sort(key=lambda x: x["count"], reverse=True)

            unique = []
            seen = set()
            for v in vendors_found:
                k = f'{v["vendor"]}:{v["model"]}'
                if k not in seen:
                    unique.append(v)
                    seen.add(k)

            if not unique:
                unique = [{"vendor": "Unknown", "model": "Unknown", "count": 0}]

            yield sse("result", {
                "device_name": device_name,
                "vendors": unique,
                "total_entries": len(unique),
                "raw_xml": fr.text
            })
            yield sse("done", {"ok": True})

        except Exception as e:
            yield sse("error", {"message": str(e)})

    return Response(generate(), mimetype='text/event-stream')


# ---------------------------
# Routes (existing)
# ---------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/clients')
def get_clients():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT id, name, status
        FROM clients
        WHERE deleted_at IS NULL
        ORDER BY name
    """
    try:
        cursor.execute(query)
        clients = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(clients)
    except Error as e:
        cursor.close()
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/<int:client_id>/summary')
def get_client_summary(client_id):
    # Get time filter parameters
    hours = request.args.get('hours', '24')
    try:
        hours = int(hours)
    except ValueError:
        hours = 24

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT 
            c.name AS client_name,
            COUNT(DISTINCT i.incident_rpt_dev_name) AS total_devices,
            COUNT(*) AS total_incidents,
            COUNT(DISTINCT DATE(i.incident_first_seen_datetime)) AS active_days,
            COUNT(DISTINCT i.id) AS unique_incidents,
            SUM(CASE WHEN i.event_severity_cat = 'HIGH' THEN 1 ELSE 0 END) AS high_severity,
            SUM(CASE WHEN i.event_severity_cat = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_severity,
            SUM(CASE WHEN i.event_severity_cat = 'LOW' THEN 1 ELSE 0 END) AS low_severity
        FROM incidents i
        INNER JOIN clients c ON i.client_id = c.id
        WHERE c.id = %s
            AND i.incident_rpt_dev_name IS NOT NULL 
            AND i.incident_rpt_dev_name != ''
            AND i.deleted_at IS NULL
            AND i.incident_first_seen_datetime >= DATE_SUB(NOW(), INTERVAL %s HOUR)
        GROUP BY c.name
    """
    try:
        cursor.execute(query, (client_id, hours))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result:
            result['time_filter_hours'] = hours
            return jsonify(result)
        return jsonify({'error': 'Client not found or no data'}), 404
    except Error as e:
        cursor.close()
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/<int:client_id>/devices')
def get_device_incidents(client_id):
    # Get time filter parameters
    hours = request.args.get('hours', '24')
    try:
        hours = int(hours)
    except ValueError:
        hours = 24

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT 
            i.incident_rpt_dev_name AS device_name,
            COUNT(*) AS incident_count,
            MIN(i.incident_first_seen_datetime) AS first_incident,
            MAX(i.incident_last_seen_datetime) AS last_incident,
            SUM(CASE WHEN i.event_severity_cat = 'HIGH' THEN 1 ELSE 0 END) AS high_severity,
            SUM(CASE WHEN i.event_severity_cat = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_severity,
            SUM(CASE WHEN i.event_severity_cat = 'LOW' THEN 1 ELSE 0 END) AS low_severity
        FROM incidents i
        WHERE i.client_id = %s
            AND i.incident_rpt_dev_name IS NOT NULL 
            AND i.incident_rpt_dev_name != ''
            AND i.deleted_at IS NULL
            AND i.incident_first_seen_datetime >= DATE_SUB(NOW(), INTERVAL %s HOUR)
        GROUP BY i.incident_rpt_dev_name
        ORDER BY incident_count DESC
    """
    try:
        cursor.execute(query, (client_id, hours))
        results = cursor.fetchall()

        for row in results:
            if row['first_incident']:
                row['first_incident'] = row['first_incident'].strftime('%Y-%m-%d %H:%M:%S')
            if row['last_incident']:
                row['last_incident'] = row['last_incident'].strftime('%Y-%m-%d %H:%M:%S')

        cursor.close()
        conn.close()
        return jsonify(results)
    except Error as e:
        cursor.close()
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/<int:client_id>/devices/with-vendor')
def get_device_incidents_with_vendor(client_id):
    # Get time filter parameters
    hours = request.args.get('hours', '24')
    try:
        hours = int(hours)
    except ValueError:
        hours = 24

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT 
            i.incident_rpt_dev_name AS device_name,
            COUNT(*) AS incident_count,
            MIN(i.incident_first_seen_datetime) AS first_incident,
            MAX(i.incident_last_seen_datetime) AS last_incident,
            SUM(CASE WHEN i.event_severity_cat = 'HIGH' THEN 1 ELSE 0 END) AS high_severity,
            SUM(CASE WHEN i.event_severity_cat = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_severity,
            SUM(CASE WHEN i.event_severity_cat = 'LOW' THEN 1 ELSE 0 END) AS low_severity
        FROM incidents i
        WHERE i.client_id = %s
            AND i.incident_rpt_dev_name IS NOT NULL 
            AND i.incident_rpt_dev_name != ''
            AND i.deleted_at IS NULL
            AND i.incident_first_seen_datetime >= DATE_SUB(NOW(), INTERVAL %s HOUR)
        GROUP BY i.incident_rpt_dev_name
        ORDER BY incident_count DESC
    """
    try:
        cursor.execute(query, (client_id, hours))
        results = cursor.fetchall()
        cursor.close()
        conn.close()

        fortisiem_cust_id = get_fortisiem_cust_id(client_id)

        for row in results:
            if row['first_incident']:
                row['first_incident'] = row['first_incident'].strftime('%Y-%m-%d %H:%M:%S')
            if row['last_incident']:
                row['last_incident'] = row['last_incident'].strftime('%Y-%m-%d %H:%M:%S')
            row['vendor'] = 'Loading...'
            row['model'] = 'Loading...'

        return jsonify({'devices': results, 'fortisiem_cust_id': fortisiem_cust_id})
    except Error as e:
        cursor.close()
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/device/vendor')
def get_device_vendor():
    device_name = request.args.get('device_name')
    fortisiem_cust_id = request.args.get('cust_id')
    client_id = request.args.get('client_id')  # For auto-saving single results
    include_debug = request.args.get('debug', 'false').lower() == 'true'

    if not device_name or not fortisiem_cust_id:
        return jsonify({'error': 'Missing device_name or cust_id parameter'}), 400

    try:
        fortisiem_cust_id = int(fortisiem_cust_id)
        if client_id:
            client_id = int(client_id)
    except ValueError:
        return jsonify({'error': 'Invalid cust_id or client_id'}), 400

    vendor_info = query_fortisiem_vendor(device_name, fortisiem_cust_id)

    if vendor_info and vendor_info.get('vendors'):
        response = {
            'device_name': device_name,
            'vendors': vendor_info['vendors'],
            'total_entries': vendor_info.get('total_entries', len(vendor_info['vendors'])),
            'vendor': vendor_info['vendors'][0]['vendor'] if vendor_info['vendors'] else 'Unknown',
            'model': vendor_info['vendors'][0]['model'] if vendor_info['vendors'] else 'Unknown',
            'single_result': vendor_info.get('single_result', False)
        }
        
        # Auto-save single results if client_id provided and result is valid
        if (client_id and vendor_info.get('single_result') and 
            vendor_info['vendors'][0]['vendor'] not in ['Unknown', 'Error']):
            try:
                save_vendor_selection(
                    client_id, 
                    device_name, 
                    vendor_info['vendors'][0]['vendor'], 
                    vendor_info['vendors'][0]['model']
                )
                response['auto_saved'] = True
                logger.info(f"Auto-saved single vendor result: {device_name} -> {vendor_info['vendors'][0]['vendor']}/{vendor_info['vendors'][0]['model']}")
            except Exception as e:
                logger.warning(f"Failed to auto-save vendor selection: {e}")
                response['auto_saved'] = False
        
        if include_debug and vendor_info.get('debug_info'):
            response['debug_info'] = vendor_info['debug_info']
        return jsonify(response)

    response = {
        'device_name': device_name,
        'vendors': [{'vendor': 'Unknown', 'model': 'Unknown', 'count': 0}],
        'total_entries': 1,
        'vendor': 'Unknown',
        'model': 'Unknown',
        'single_result': False
    }
    return jsonify(response)


@app.route('/api/client/<int:client_id>/devices/vendors')
def get_all_device_vendors(client_id):
    include_debug = request.args.get('debug', 'false').lower() == 'true'
    # Get time filter parameters
    hours = request.args.get('hours', '24')
    try:
        hours = int(hours)
    except ValueError:
        hours = 24

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT DISTINCT i.incident_rpt_dev_name AS device_name
        FROM incidents i
        WHERE i.client_id = %s
            AND i.incident_rpt_dev_name IS NOT NULL 
            AND i.incident_rpt_dev_name != ''
            AND i.deleted_at IS NULL
            AND i.incident_first_seen_datetime >= DATE_SUB(NOW(), INTERVAL %s HOUR)
    """
    try:
        cursor.execute(query, (client_id, hours))
        devices = cursor.fetchall()
        cursor.close()
        conn.close()

        if not devices:
            return jsonify({'vendors': {}})

        fortisiem_cust_id = get_fortisiem_cust_id(client_id)

        vendors = {}
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_device = {
                executor.submit(query_fortisiem_vendor, d['device_name'], fortisiem_cust_id): d['device_name']
                for d in devices
            }

            for future in as_completed(future_to_device):
                device_name = future_to_device[future]
                try:
                    vendor_info = future.result()
                    if vendor_info and vendor_info.get('vendors'):
                        device_vendors = {
                            'vendors': vendor_info['vendors'],
                            'total_entries': vendor_info.get('total_entries', len(vendor_info['vendors'])),
                            'vendor': vendor_info['vendors'][0]['vendor'],
                            'model': vendor_info['vendors'][0]['model'],
                            'single_result': vendor_info.get('single_result', False)
                        }
                        
                        # Auto-save single results
                        if (vendor_info.get('single_result') and 
                            vendor_info['vendors'][0]['vendor'] not in ['Unknown', 'Error']):
                            try:
                                save_vendor_selection(
                                    client_id, 
                                    device_name, 
                                    vendor_info['vendors'][0]['vendor'], 
                                    vendor_info['vendors'][0]['model']
                                )
                                device_vendors['auto_saved'] = True
                                logger.info(f"Auto-saved single vendor result: {device_name} -> {vendor_info['vendors'][0]['vendor']}/{vendor_info['vendors'][0]['model']}")
                            except Exception as e:
                                logger.warning(f"Failed to auto-save vendor selection for {device_name}: {e}")
                                device_vendors['auto_saved'] = False
                        
                        if include_debug and vendor_info.get('debug_info'):
                            device_vendors['debug_info'] = vendor_info['debug_info']
                        vendors[device_name] = device_vendors
                    else:
                        fallback = {
                            'vendors': [{'vendor': 'Unknown', 'model': 'Unknown', 'count': 0}],
                            'total_entries': 1,
                            'vendor': 'Unknown',
                            'model': 'Unknown'
                        }
                        vendors[device_name] = fallback
                except Exception as e:
                    err = {
                        'vendors': [{'vendor': 'Error', 'model': 'Error', 'count': 0}],
                        'total_entries': 1,
                        'vendor': 'Error',
                        'model': 'Error'
                    }
                    if include_debug:
                        err['debug_info'] = {'device_name': device_name, 'errors': [str(e)]}
                    vendors[device_name] = err

        return jsonify({'vendors': vendors})

    except Error as e:
        cursor.close()
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/client/<int:client_id>/export')
def export_client_data(client_id):
    include_vendor = request.args.get('include_vendor', 'false').lower() == 'true'
    # Get time filter parameters
    hours = request.args.get('hours', '24')
    try:
        hours = int(hours)
    except ValueError:
        hours = 24

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT name FROM clients WHERE id = %s", (client_id,))
    client = cursor.fetchone()
    if not client:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Client not found'}), 404

    query = """
        SELECT 
            i.incident_rpt_dev_name AS 'Device Name',
            COUNT(*) AS 'Incident Count',
            MIN(i.incident_first_seen_datetime) AS 'First Seen',
            MAX(i.incident_last_seen_datetime) AS 'Last Seen',
            SUM(CASE WHEN i.event_severity_cat = 'HIGH' THEN 1 ELSE 0 END) AS 'High Severity',
            SUM(CASE WHEN i.event_severity_cat = 'MEDIUM' THEN 1 ELSE 0 END) AS 'Medium Severity',
            SUM(CASE WHEN i.event_severity_cat = 'LOW' THEN 1 ELSE 0 END) AS 'Low Severity'
        FROM incidents i
        WHERE i.client_id = %s
            AND i.incident_rpt_dev_name IS NOT NULL 
            AND i.incident_rpt_dev_name != ''
            AND i.deleted_at IS NULL
            AND i.incident_first_seen_datetime >= DATE_SUB(NOW(), INTERVAL %s HOUR)
        GROUP BY i.incident_rpt_dev_name
        ORDER BY COUNT(*) DESC
    """

    try:
        cursor.execute(query, (client_id, hours))
        results = cursor.fetchall()
        cursor.close()
        conn.close()

        if include_vendor and results:
            fortisiem_cust_id = get_fortisiem_cust_id(client_id)

            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_row = {
                    executor.submit(query_fortisiem_vendor, row['Device Name'], fortisiem_cust_id): row
                    for row in results
                }
                for future in as_completed(future_to_row):
                    row = future_to_row[future]
                    try:
                        vendor_info = future.result()
                        if vendor_info and vendor_info.get('vendors'):
                            primary = vendor_info['vendors'][0]
                            row['Vendor'] = primary['vendor']
                            row['Model'] = primary['model']
                            row['Vendor Count'] = primary['count']

                            if len(vendor_info['vendors']) > 1:
                                additional = [f"{v['vendor']}/{v['model']} ({v['count']})" for v in vendor_info['vendors'][1:]]
                                row['Additional Vendors'] = '; '.join(additional)
                            else:
                                row['Additional Vendors'] = ''
                        else:
                            row['Vendor'] = 'Unknown'
                            row['Model'] = 'Unknown'
                            row['Vendor Count'] = 0
                            row['Additional Vendors'] = ''
                    except Exception:
                        row['Vendor'] = 'Error'
                        row['Model'] = 'Error'
                        row['Vendor Count'] = 0
                        row['Additional Vendors'] = ''

        output = io.StringIO()
        if results:
            fieldnames = list(results[0].keys())
            if include_vendor:
                vendor_fields = ['Vendor', 'Model', 'Vendor Count', 'Additional Vendors']
                non_vendor_fields = [f for f in fieldnames if f not in ['Device Name'] + vendor_fields]
                fieldnames = ['Device Name'] + vendor_fields + non_vendor_fields

            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                if row.get('First Seen'):
                    row['First Seen'] = row['First Seen'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(row['First Seen'], 'strftime') else row['First Seen']
                if row.get('Last Seen'):
                    row['Last Seen'] = row['Last Seen'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(row['Last Seen'], 'strftime') else row['Last Seen']
                writer.writerow(row)

        output.seek(0)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"device_incidents_{client['name'].replace(' ', '_')}_{timestamp}.csv"

        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
    except Error as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    # Get time filter parameters
    hours = request.args.get('hours', '24')
    try:
        hours = int(hours)
    except ValueError:
        hours = 24

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT 
            COUNT(DISTINCT c.id) AS total_clients,
            COUNT(DISTINCT i.incident_rpt_dev_name) AS total_devices,
            COUNT(*) AS total_incidents,
            SUM(CASE WHEN i.event_severity_cat = 'HIGH' THEN 1 ELSE 0 END) AS high_severity_count,
            COUNT(DISTINCT DATE(i.incident_first_seen_datetime)) AS active_days
        FROM incidents i
        INNER JOIN clients c ON i.client_id = c.id
        WHERE i.deleted_at IS NULL
            AND c.deleted_at IS NULL
            AND i.incident_rpt_dev_name IS NOT NULL 
            AND i.incident_rpt_dev_name != ''
            AND i.incident_first_seen_datetime >= DATE_SUB(NOW(), INTERVAL %s HOUR)
    """
    try:
        cursor.execute(query, (hours,))
        result = cursor.fetchone()
        if result:
            result['time_filter_hours'] = hours
        cursor.close()
        conn.close()
        return jsonify(result)
    except Error as e:
        cursor.close()
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/top-devices')
def get_top_devices():
    # Get time filter parameters
    hours = request.args.get('hours', '24')
    try:
        hours = int(hours)
    except ValueError:
        hours = 24

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT 
            c.name AS client_name,
            i.incident_rpt_dev_name AS device_name,
            COUNT(*) AS incident_count
        FROM incidents i
        INNER JOIN clients c ON i.client_id = c.id
        WHERE i.incident_rpt_dev_name IS NOT NULL 
            AND i.incident_rpt_dev_name != ''
            AND i.deleted_at IS NULL
            AND c.deleted_at IS NULL
            AND i.incident_first_seen_datetime >= DATE_SUB(NOW(), INTERVAL %s HOUR)
        GROUP BY c.name, i.incident_rpt_dev_name
        ORDER BY incident_count DESC
        LIMIT 10
    """
    try:
        cursor.execute(query, (hours,))
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(results)
    except Error as e:
        cursor.close()
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/cache/clear')
def clear_vendor_cache():
    cache_size_before = len(vendor_cache)
    with vendor_cache_lock:
        vendor_cache.clear()
    return jsonify({'status': 'ok', 'message': f'Vendor cache cleared - removed {cache_size_before} entries'})


@app.route('/api/debug/device-query', methods=['POST'])
def debug_device_query():
    data = request.get_json()
    if not data or not data.get('device_name') or not data.get('client_id'):
        return jsonify({'error': 'Missing device_name or client_id in request body'}), 400

    device_name = data['device_name']
    client_id = data['client_id']

    try:
        fortisiem_cust_id = get_fortisiem_cust_id(client_id)
        vendor_info = query_fortisiem_vendor(device_name, fortisiem_cust_id)
        return jsonify({
            'device_name': device_name,
            'client_id': client_id,
            'fortisiem_cust_id': fortisiem_cust_id,
            'result': vendor_info
        })
    except Exception as e:
        return jsonify({'device_name': device_name, 'client_id': client_id, 'error': str(e)}), 500


@app.route('/api/device/vendor/select', methods=['POST'])
def select_device_vendor():
    """Select the correct vendor for a device when multiple options exist"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    device_name = data.get('device_name')
    client_id = data.get('client_id') 
    selected_vendor = data.get('vendor')
    selected_model = data.get('model')
    
    if not all([device_name, client_id, selected_vendor, selected_model]):
        return jsonify({'error': 'Missing required fields: device_name, client_id, vendor, model'}), 400
    
    try:
        client_id = int(client_id)
    except ValueError:
        return jsonify({'error': 'Invalid client_id'}), 400
    
    try:
        success = save_vendor_selection(client_id, device_name, selected_vendor, selected_model)
        
        if success:
            logger.info(f"Vendor selection saved: client={client_id}, device={device_name}, vendor={selected_vendor}, model={selected_model}")
            return jsonify({
                'status': 'success',
                'message': 'Vendor selection saved successfully',
                'device_name': device_name,
                'vendor': selected_vendor,
                'model': selected_model
            })
        else:
            return jsonify({'error': 'Failed to save vendor selection'}), 500
            
    except Exception as e:
        logger.error(f"Error saving vendor selection: {e}")
        return jsonify({'error': f'Error: {str(e)}'}), 500


@app.route('/api/device/vendor/manual', methods=['POST'])
def manual_device_vendor():
    """Manually set vendor and model for a device"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    device_name = data.get('device_name')
    client_id = data.get('client_id') 
    vendor = data.get('vendor', '').strip()
    model = data.get('model', '').strip()
    
    if not all([device_name, client_id]):
        return jsonify({'error': 'Missing required fields: device_name, client_id'}), 400
    
    if not vendor:
        return jsonify({'error': 'Vendor name is required'}), 400
        
    if not model:
        model = 'Unknown'
    
    try:
        client_id = int(client_id)
    except ValueError:
        return jsonify({'error': 'Invalid client_id'}), 400
    
    try:
        success = save_vendor_selection(client_id, device_name, vendor, model)
        
        if success:
            logger.info(f"Manual vendor selection saved: client={client_id}, device={device_name}, vendor={vendor}, model={model}")
            return jsonify({
                'status': 'success',
                'message': 'Manual vendor selection saved successfully',
                'device_name': device_name,
                'vendor': vendor,
                'model': model
            })
        else:
            return jsonify({'error': 'Failed to save manual vendor selection'}), 500
            
    except Exception as e:
        logger.error(f"Error saving manual vendor selection: {e}")
        return jsonify({'error': f'Error: {str(e)}'}), 500


@app.route('/api/device/vendor/selections')
def get_device_vendor_selections_api():
    """Get all device vendor selections for a client"""
    client_id = request.args.get('client_id')
    
    if not client_id:
        return jsonify({'error': 'Missing client_id parameter'}), 400
    
    try:
        client_id = int(client_id)
    except ValueError:
        return jsonify({'error': 'Invalid client_id'}), 400
    
    try:
        selections = get_client_vendor_selections(client_id)
        return jsonify({'selections': selections})
        
    except Exception as e:
        logger.error(f"Error getting vendor selections: {e}")
        return jsonify({'error': f'Error: {str(e)}'}), 500


@app.route('/api/vendor/incidents/summary')
def get_vendor_incidents_summary():
    """Generate vendor incidents summary showing 'this vendor has this many incidents'"""
    client_id = request.args.get('client_id')
    # Get time filter parameters
    hours = request.args.get('hours', '24')
    try:
        hours = int(hours)
    except ValueError:
        hours = 24
    
    if not client_id:
        return jsonify({'error': 'Missing client_id parameter'}), 400
    
    try:
        client_id = int(client_id)
    except ValueError:
        return jsonify({'error': 'Invalid client_id'}), 400
    
    try:
        # Get device incidents from database
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Get incident counts by device including true incident counts
        query = """
            SELECT 
                i.incident_rpt_dev_name AS device_name,
                COUNT(*) AS incident_count,
                SUM(CASE WHEN i.event_severity_cat = 'HIGH' THEN 1 ELSE 0 END) AS high_severity,
                SUM(CASE WHEN i.event_severity_cat = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_severity,
                SUM(CASE WHEN i.event_severity_cat = 'LOW' THEN 1 ELSE 0 END) AS low_severity,
                COUNT(CASE WHEN i.latest_incident_status = 5 AND t.incident_type = 'True Incident' THEN 1 END) AS true_incident_count,
                MIN(i.incident_first_seen_datetime) AS first_incident,
                MAX(i.incident_last_seen_datetime) AS last_incident
            FROM incidents i
            LEFT JOIN incident_statuses t ON i.id = t.incident_id
            WHERE i.client_id = %s
                AND i.incident_rpt_dev_name IS NOT NULL 
                AND i.incident_rpt_dev_name != ''
                AND i.deleted_at IS NULL
                AND i.incident_first_seen_datetime >= DATE_SUB(NOW(), INTERVAL %s HOUR)
            GROUP BY i.incident_rpt_dev_name
            ORDER BY COUNT(*) DESC
        """
        cursor.execute(query, (client_id, hours))
        device_results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        # Get vendor selections from Excel
        vendor_selections = get_client_vendor_selections(client_id)
        vendor_selection_dict = {vs['device_name']: vs for vs in vendor_selections}
        
        # Aggregate by model first, then track vendors for each model
        model_summary = {}
        vendor_summary = {}
        unselected_devices = []
        
        for device in device_results:
            device_name = device['device_name']
            vendor_selection = vendor_selection_dict.get(device_name)
            
            if vendor_selection:
                vendor = vendor_selection.get('selected_vendor', 'Unknown')
                model = vendor_selection.get('selected_model', 'Unknown')
                
                # Create model entry if it doesn't exist
                model_key = f"{vendor}:{model}"  # Use vendor:model as key to avoid conflicts
                if model_key not in model_summary:
                    model_summary[model_key] = {
                        'model': model,
                        'vendor': vendor,
                        'total_incidents': 0,
                        'true_incidents': 0,
                        'high_severity': 0,
                        'medium_severity': 0,
                        'low_severity': 0,
                        'device_count': 0,
                        'devices': []
                    }
                
                # Update model totals
                model_summary[model_key]['total_incidents'] += device['incident_count']
                model_summary[model_key]['true_incidents'] += device['true_incident_count'] or 0
                model_summary[model_key]['high_severity'] += device['high_severity'] or 0
                model_summary[model_key]['medium_severity'] += device['medium_severity'] or 0
                model_summary[model_key]['low_severity'] += device['low_severity'] or 0
                model_summary[model_key]['device_count'] += 1
                
                # Add device details to model
                model_summary[model_key]['devices'].append({
                    'device_name': device['device_name'],
                    'incident_count': device['incident_count'],
                    'true_incident_count': device['true_incident_count'] or 0,
                    'high_severity': device['high_severity'] or 0,
                    'medium_severity': device['medium_severity'] or 0,
                    'low_severity': device['low_severity'] or 0,
                    'first_incident': device['first_incident'].strftime('%Y-%m-%d %H:%M:%S') if device['first_incident'] else None,
                    'last_incident': device['last_incident'].strftime('%Y-%m-%d %H:%M:%S') if device['last_incident'] else None
                })
                
                # Also maintain vendor summary for summary lines
                if vendor not in vendor_summary:
                    vendor_summary[vendor] = {'total_incidents': 0, 'true_incidents': 0, 'device_count': 0}
                vendor_summary[vendor]['total_incidents'] += device['incident_count']
                vendor_summary[vendor]['true_incidents'] += device['true_incident_count'] or 0
                vendor_summary[vendor]['device_count'] += 1
                
            else:
                # Device without vendor selection
                unselected_devices.append({
                    'device_name': device['device_name'],
                    'incident_count': device['incident_count'],
                    'true_incident_count': device['true_incident_count'] or 0,
                    'high_severity': device['high_severity'] or 0,
                    'medium_severity': device['medium_severity'] or 0,
                    'low_severity': device['low_severity'] or 0,
                    'first_incident': device['first_incident'].strftime('%Y-%m-%d %H:%M:%S') if device['first_incident'] else None,
                    'last_incident': device['last_incident'].strftime('%Y-%m-%d %H:%M:%S') if device['last_incident'] else None
                })
        
        # Convert to list and sort by incident count
        model_list = list(model_summary.values())
        model_list.sort(key=lambda x: x['total_incidents'], reverse=True)
        
        # Create vendor list for summary lines
        vendor_list = []
        for vendor, data in vendor_summary.items():
            vendor_list.append({
                'vendor': vendor,
                'total_incidents': data['total_incidents'],
                'true_incidents': data['true_incidents'],
                'device_count': data['device_count']
            })
        vendor_list.sort(key=lambda x: x['total_incidents'], reverse=True)
        
        # Create summary lines
        summary_lines = []
        for vendor in vendor_list:
            line = f"{vendor['vendor']}: {vendor['total_incidents']} incidents ({vendor['true_incidents']} true incidents) across {vendor['device_count']} devices"
            summary_lines.append(line)
        
        return jsonify({
            'model_summary': model_list,
            'vendor_summary': vendor_list,
            'unselected_devices': unselected_devices,
            'summary_lines': summary_lines,
            'total_models': len(model_list),
            'total_vendors': len(vendor_list),
            'total_unselected_devices': len(unselected_devices)
        })
        
    except Exception as e:
        logger.error(f"Error getting vendor incidents summary: {e}")
        return jsonify({'error': f'Error: {str(e)}'}), 500


@app.route('/api/vendors/rules')
def get_vendor_rules():
    """Get rules for specified vendors"""
    vendor_list = request.args.getlist('vendors')  # Can accept multiple vendors
    
    if not vendor_list:
        return jsonify({'error': 'Missing vendors parameter. Provide one or more vendor names.'}), 400
    
    try:
        logger.info(f"Getting rules for vendors: {vendor_list}")
        
        vendor_rules = get_rules_for_vendors(vendor_list)
        
        # Count total rules
        total_rules = sum(len(rules) for rules in vendor_rules.values())
        
        return jsonify({
            'vendors': vendor_list,
            'vendor_rules': vendor_rules,
            'total_vendors': len(vendor_rules),
            'total_rules': total_rules,
            'summary': {
                vendor: {
                    'rule_count': len(rules),
                    'functions': list(set(rule['function'] for rule in rules if rule['function'])),
                    'categories': list(set(rule['category'] for rule in rules if rule['category']))
                }
                for vendor, rules in vendor_rules.items()
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting vendor rules: {e}")
        return jsonify({'error': f'Error: {str(e)}'}), 500


@app.route('/api/vendors/available')
def get_available_vendors():
    """Get list of all available vendors from rules data"""
    try:
        rules_data = load_rules_data()
        
        vendor_stats = {}
        for vendor, rules in rules_data.items():
            vendor_stats[vendor] = {
                'rule_count': len(rules),
                'functions': list(set(rule['function'] for rule in rules if rule['function'])),
                'categories': list(set(rule['category'] for rule in rules if rule['category']))
            }
        
        # Sort by rule count descending
        sorted_vendors = sorted(vendor_stats.items(), key=lambda x: x[1]['rule_count'], reverse=True)
        
        return jsonify({
            'vendors': dict(sorted_vendors),
            'total_vendors': len(vendor_stats),
            'total_rules': sum(len(rules) for rules in rules_data.values())
        })
        
    except Exception as e:
        logger.error(f"Error getting available vendors: {e}")
        return jsonify({'error': f'Error: {str(e)}'}), 500


@app.route('/api/rules/refresh', methods=['POST'])
def refresh_rules_data():
    """Force refresh of rules data from FortiSIEM"""
    try:
        logger.info("Manual refresh of rules data requested")
        
        # Clear the cache and reload
        with rules_cache_lock:
            rules_cache.clear()
        
        rules_data = load_rules_data(force_refresh=True)
        
        total_vendors = len(rules_data)
        total_rules = sum(len(rules) for rules in rules_data.values())
        
        logger.info(f"Rules data refreshed: {total_vendors} vendors, {total_rules} rules")
        
        return jsonify({
            'status': 'success',
            'message': 'Rules data refreshed successfully',
            'total_vendors': total_vendors,
            'total_rules': total_rules,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error refreshing rules data: {e}")
        return jsonify({'error': f'Error: {str(e)}'}), 500


@app.route('/api/vendors/rules/search')
def search_vendor_rules():
    """Search rules by vendor name or rule name"""
    search_term = request.args.get('q', '').strip()
    
    if not search_term or len(search_term) < 2:
        return jsonify({'error': 'Search term must be at least 2 characters long'}), 400
    
    try:
        rules_data = load_rules_data()
        matching_results = {}
        
        search_lower = search_term.lower()
        
        for vendor, rules in rules_data.items():
            vendor_matches = []
            
            # Check if vendor name matches
            vendor_matches_name = search_lower in vendor.lower()
            
            for rule in rules:
                # Check if rule name matches
                rule_matches = search_lower in rule['name'].lower()
                
                if vendor_matches_name or rule_matches:
                    vendor_matches.append({
                        **rule,
                        'match_type': 'vendor' if vendor_matches_name else 'rule'
                    })
            
            if vendor_matches:
                matching_results[vendor] = vendor_matches
        
        total_matches = sum(len(rules) for rules in matching_results.values())
        
        return jsonify({
            'search_term': search_term,
            'matching_vendors': len(matching_results),
            'total_matching_rules': total_matches,
            'results': matching_results
        })
        
    except Exception as e:
        logger.error(f"Error searching vendor rules: {e}")
        return jsonify({'error': f'Error: {str(e)}'}), 500


if __name__ == '__main__':
    print("""
┌──────────────────────────────────────────────────────────────────────────────┐
│ DEVICE INCIDENT ANALYZER - WEB APPLICATION                                   │
│ Live GUI: XML Query + Progress + Result (SSE)                                │
│ Logs written to: app_debug.log                                               │
└──────────────────────────────────────────────────────────────────────────────┘
    """)

    port = int(os.getenv('PORT', 5002))
    logger.info(f"Starting Flask on 0.0.0.0:{port}")
    logger.info(f"DB: {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}")
    logger.info(f"FortiSIEM: {FORTISIEM_CONFIG['ip']} verify_ssl={FORTISIEM_CONFIG['verify_ssl']}")
    logger.info(f"Debug: {DEBUG_MODE}")

    app.run(debug=True, host='0.0.0.0', port=port)
