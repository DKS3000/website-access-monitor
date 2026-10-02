#!/usr/bin/env python3
import csv
import io
import json
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime

import requests
from flask import Flask, Response, jsonify, render_template, request

from config import DEFAULT_TARGET_URL, validate_target_url
from diagnostics import run_diagnostics

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
HISTORY_FILE = os.path.join(LOG_DIR, 'history.json')
ROUTES_FILE = os.path.join(BASE_DIR, 'routes.json')
MAX_HISTORY = 100

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32).hex()

lock = threading.RLock()

monitoring_status = {
    'running': False,
    'current_country': 'US',
    'current_route': 'direct',
    'target_url': DEFAULT_TARGET_URL,
    'current_result': None,
    'last_updated': None,
    'results_history': [],
    'vpn_connected': False,
    'current_vpn_country': None,
    'attempts': 0,
    'max_attempts': 30,
    'interval': 2,
    'success': False,
    'schedule_minutes': 0,
    'starting': False,
}

VPN_COUNTRIES = {
    'US': 'us',
    'UK': 'uk',
    'DE': 'de',
    'FR': 'fr',
    'IN': 'in',
    'SG': 'sg',
    'JP': 'jp',
    'CA': 'ca',
    'AU': 'au',
}


# ---------------------------------------------------------------- VPN helpers
def vpn_available():
    """True when the nordvpn binary is installed."""
    return shutil.which('nordvpn') is not None


def _nordvpn_status_output():
    if not vpn_available():
        return ''
    try:
        result = subprocess.run(['nordvpn', 'status'], capture_output=True, text=True, timeout=5)
        return result.stdout
    except Exception:
        return ''


def check_vpn_status():
    """Check if NordVPN is connected (False when not installed)"""
    output = _nordvpn_status_output().lower()
    return 'status: connected' in output or ('connected' in output and 'disconnected' not in output)


def get_vpn_country():
    """Get current VPN country (None when unavailable)"""
    for line in _nordvpn_status_output().split('\n'):
        if 'country' in line.lower() and ':' in line:
            return line.split(':', 1)[1].strip()
    return None


def connect_vpn(country_code):
    """Connect to NordVPN country"""
    if not vpn_available():
        return False
    try:
        print(f"Connecting to NordVPN: {country_code}")
        result = subprocess.run(['nordvpn', 'connect', country_code],
                                capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            time.sleep(3)  # Wait for connection to stabilize
            return True
        return False
    except Exception as e:
        print(f"Error connecting VPN: {e}")
        return False


# ------------------------------------------------------------- routes/config
def load_routes():
    try:
        with open(ROUTES_FILE, 'r', encoding='utf-8') as fh:
            routes = json.load(fh).get('routes', [])
    except (OSError, ValueError):
        routes = []
    return routes or [{'name': 'direct', 'type': 'direct', 'description': 'Direct connection'}]


def list_routes():
    """All selectable routes: direct, VPN countries (if available), routes.json entries."""
    out = [{'id': 'direct', 'name': 'Direct', 'type': 'direct'}]
    if vpn_available():
        for code in VPN_COUNTRIES:
            out.append({'id': 'vpn:' + code, 'name': 'VPN ' + code, 'type': 'vpn'})
    for r in load_routes():
        if r.get('type') == 'direct':
            continue
        if r.get('type') == 'proxy' and r.get('proxy_url'):
            out.append({'id': 'route:' + r.get('name', 'proxy'), 'name': r.get('name', 'proxy'),
                        'type': 'proxy', 'description': r.get('description', '')})
    return out


def resolve_route(route_id):
    """Return (route dict for diagnostics, label)."""
    route_id = route_id or 'direct'
    if route_id.startswith('route:'):
        name = route_id[6:]
        for r in load_routes():
            if r.get('name') == name:
                return r, name
        raise ValueError('Unknown route: %s' % route_id)
    if route_id.startswith('vpn:'):
        code = route_id[4:]
        if code not in VPN_COUNTRIES:
            raise ValueError('Unknown VPN country: %s' % code)
        return {'name': route_id, 'type': 'direct'}, code
    if route_id == 'direct':
        return {'name': 'direct', 'type': 'direct'}, 'Direct'
    raise ValueError('Unknown route: %s' % route_id)


# ------------------------------------------------------------------- history
def load_history():
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        if isinstance(data, list):
            monitoring_status['results_history'] = data[-MAX_HISTORY:]
    except (OSError, ValueError):
        pass


def save_history():
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        tmp = HISTORY_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(monitoring_status['results_history'], fh, indent=2)
        os.replace(tmp, HISTORY_FILE)
    except OSError as e:
        print(f"Could not save history: {e}")


def add_history(entry):
    with lock:
        monitoring_status['results_history'].append(entry)
        del monitoring_status['results_history'][:-MAX_HISTORY]
        save_history()


def run_test(target_url, route_id='direct', attempt=0, record=True):
    """Run one diagnostic test and optionally store it in history."""
    route, label = resolve_route(route_id)
    result = run_diagnostics(target_url, route)
    result['country'] = label
    result['route_id'] = route_id
    result['attempt'] = attempt
    # backward compatible shape used by /api/status
    legacy = {'target': target_url, 'timestamp': result['timestamp'], 'results': [result]}
    with lock:
        monitoring_status['current_result'] = legacy
        monitoring_status['last_updated'] = result['timestamp']
    if record:
        add_history({'timestamp': result['timestamp'], 'country': label, 'route': route_id,
                     'attempt': attempt, 'status': result['status'],
                     'http_status': result['http_status'],
                     'response_time_ms': result['response_time_ms'],
                     'error': result['error'], 'target': target_url, 'result': legacy})
    return result


# --------------------------------------------------------------- public IP
_ip_cache = {'ts': 0, 'data': None}


def get_public_ip():
    if time.time() - _ip_cache['ts'] < 30 and _ip_cache['data']:
        return _ip_cache['data']
    try:
        r = requests.get('http://ip-api.com/json/?fields=status,query,country,countryCode,isp',
                         timeout=4)
        j = r.json()
        data = {'ip': j.get('query'), 'country': j.get('country'), 'isp': j.get('isp')}
    except Exception:
        data = {'ip': None, 'country': None, 'isp': None}
    _ip_cache.update(ts=time.time(), data=data)
    return data


# -------------------------------------------------------------- monitoring
def monitoring_loop_until_success():
    """Keep testing until page opens successfully"""
    monitoring_status['attempts'] = 0
    monitoring_status['success'] = False

    while monitoring_status['running'] and monitoring_status['attempts'] < monitoring_status['max_attempts']:
        monitoring_status['attempts'] += 1
        n = monitoring_status['attempts']
        print(f"Attempt {n}/{monitoring_status['max_attempts']} - Testing {monitoring_status['target_url']}")
        try:
            result = run_test(monitoring_status['target_url'], monitoring_status['current_route'], n)
        except ValueError as e:
            monitoring_status['current_result'] = {'error': str(e)}
            break
        if result['status'] == 'success':
            monitoring_status['success'] = True
            monitoring_status['running'] = False
            print(f"SUCCESS! Page opened on attempt {n}")
            break
        for _ in range(int(monitoring_status['interval'] * 10)):
            if not monitoring_status['running']:
                break
            time.sleep(0.1)
    monitoring_status['running'] = False


def scheduler_loop():
    """In-process scheduled monitoring: one test every N minutes."""
    last_run = 0.0
    while True:
        time.sleep(1)
        minutes = monitoring_status['schedule_minutes']
        if not minutes or monitoring_status['running']:
            continue
        if time.time() - last_run >= minutes * 60:
            last_run = time.time()
            try:
                run_test(monitoring_status['target_url'], monitoring_status['current_route'])
            except Exception as e:
                print(f"Scheduled test failed: {e}")


def _json_body():
    return request.get_json(silent=True) or {}


# ------------------------------------------------------------------- routes
@app.route('/')
def index():
    return render_template('dashboard_enhanced.html', vpn_countries=VPN_COUNTRIES,
                           default_target=DEFAULT_TARGET_URL)


@app.route('/api/status')
def get_status():
    vpn_ok = vpn_available()
    vpn_status = check_vpn_status() if vpn_ok else False
    monitoring_status['vpn_connected'] = vpn_status
    current = monitoring_status['current_result']
    return jsonify({
        'running': monitoring_status['running'],
        'country': monitoring_status['current_country'],
        'route': monitoring_status['current_route'],
        'target_url': monitoring_status['target_url'],
        'last_updated': monitoring_status['last_updated'],
        'current_result': current,
        'vpn_available': vpn_ok,
        'vpn_connected': vpn_status,
        'vpn_country': get_vpn_country() if vpn_status else None,
        'public_ip': get_public_ip(),
        'attempts': monitoring_status['attempts'],
        'max_attempts': monitoring_status['max_attempts'],
        'interval': monitoring_status['interval'],
        'schedule_minutes': monitoring_status['schedule_minutes'],
        'success': monitoring_status['success'],
    })


@app.route('/api/config', methods=['GET', 'POST'])
def config_endpoint():
    if request.method == 'POST':
        data = _json_body()
        try:
            if 'target_url' in data:
                monitoring_status['target_url'] = validate_target_url(data['target_url'])
            if 'interval' in data:
                monitoring_status['interval'] = max(0.5, min(float(data['interval']), 3600))
            if 'max_attempts' in data:
                monitoring_status['max_attempts'] = max(1, min(int(data['max_attempts']), 1000))
            if 'schedule_minutes' in data:
                monitoring_status['schedule_minutes'] = max(0, min(float(data['schedule_minutes']), 1440))
            if 'route' in data:
                resolve_route(data['route'])
                monitoring_status['current_route'] = data['route']
        except (ValueError, TypeError) as e:
            return jsonify({'status': 'error', 'error': str(e)}), 400
    cfg = {k: monitoring_status[k] for k in
           ('target_url', 'interval', 'max_attempts', 'schedule_minutes')}
    cfg.update(route=monitoring_status['current_route'], default_target_url=DEFAULT_TARGET_URL)
    return jsonify(cfg)


@app.route('/api/routes')
def get_routes():
    return jsonify({'vpn_available': vpn_available(), 'routes': list_routes()})


@app.route('/api/test-once', methods=['POST'])
def test_once():
    data = _json_body()
    try:
        target = validate_target_url(data.get('target_url') or monitoring_status['target_url'])
        monitoring_status['target_url'] = target
        route_id = data.get('route') or monitoring_status['current_route']
        route, label = resolve_route(route_id)
        if route_id.startswith('vpn:'):
            if not vpn_available():
                return jsonify({'status': 'error', 'error': 'VPN not available'}), 400
            if not connect_vpn(VPN_COUNTRIES[route_id[4:]]):
                return jsonify({'status': 'error', 'error': 'VPN connection failed'}), 502
        monitoring_status['current_route'] = route_id
        return jsonify(run_test(target, route_id))
    except ValueError as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400


@app.route('/api/compare', methods=['POST'])
def compare():
    """Run the same target across all configured (non-VPN) routes."""
    data = _json_body()
    try:
        target = validate_target_url(data.get('target_url') or monitoring_status['target_url'])
    except ValueError as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400
    results = []
    for r in list_routes():
        if r['type'] == 'vpn':
            continue  # switching VPN country mid-compare would disturb the other tests
        results.append(run_test(target, r['id']))
    return jsonify({'target': target, 'results': results})


@app.route('/api/start', methods=['POST'])
def start_testing():
    """Start VPN connection (if requested/available) and test until success"""
    with lock:
        if monitoring_status['running'] or monitoring_status['starting']:
            return jsonify({'status': 'already running'})
        monitoring_status['starting'] = True
    try:
        return _start_testing()
    finally:
        monitoring_status['starting'] = False


def _start_testing():
    data = _json_body()
    country = data.get('country', 'US')
    try:
        target_url = validate_target_url(data.get('target_url') or monitoring_status['target_url'])
        route_id = data.get('route')
        if not route_id:
            route_id = 'vpn:' + country if (data.get('country') and vpn_available()
                                            and country in VPN_COUNTRIES) else 'direct'
        resolve_route(route_id)
        if 'interval' in data:
            monitoring_status['interval'] = max(0.5, min(float(data['interval']), 3600))
        if 'max_attempts' in data:
            monitoring_status['max_attempts'] = max(1, min(int(data['max_attempts']), 1000))
    except (ValueError, TypeError) as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400
    if route_id.startswith('vpn:') and not vpn_available():
        return jsonify({'status': 'error', 'error': 'VPN not available'}), 400

    monitoring_status.update(running=True, current_country=country, current_route=route_id,
                             target_url=target_url, attempts=0, success=False)

    def connect_and_test():
        if route_id.startswith('vpn:'):
            if not connect_vpn(VPN_COUNTRIES[route_id[4:]]):
                monitoring_status['current_result'] = {'error': 'VPN connection failed'}
                monitoring_status['running'] = False
                return
            monitoring_status['vpn_connected'] = True
            time.sleep(2)
        monitoring_loop_until_success()

    threading.Thread(target=connect_and_test, daemon=True).start()
    return jsonify({'status': 'started', 'country': country, 'route': route_id})


@app.route('/api/stop', methods=['POST'])
def stop_testing():
    """Stop testing"""
    monitoring_status['running'] = False
    return jsonify({'status': 'stopped'})


@app.route('/api/history')
def get_history():
    return jsonify(monitoring_status['results_history'])


def _flat_history():
    rows = []
    for h in monitoring_status['results_history']:
        rows.append({
            'timestamp': h.get('timestamp'), 'route': h.get('country'),
            'target': h.get('target'), 'status': h.get('status'),
            'http_status': h.get('http_status'),
            'response_time_ms': h.get('response_time_ms'), 'error': h.get('error'),
        })
    return rows


@app.route('/api/export/json')
def export_json():
    return Response(json.dumps(monitoring_status['results_history'], indent=2),
                    mimetype='application/json',
                    headers={'Content-Disposition': 'attachment; filename=history.json'})


@app.route('/api/export/csv')
def export_csv():
    out = io.StringIO()
    fields = ['timestamp', 'route', 'target', 'status', 'http_status', 'response_time_ms', 'error']
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    writer.writerows(_flat_history())
    return Response(out.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=history.csv'})


@app.route('/api/vpn/disconnect', methods=['POST'])
def disconnect_vpn():
    """Disconnect VPN"""
    if not vpn_available():
        return jsonify({'status': 'VPN not available'}), 400
    try:
        subprocess.run(['nordvpn', 'disconnect'], capture_output=True, timeout=10)
        monitoring_status['vpn_connected'] = False
        return jsonify({'status': 'disconnected'})
    except Exception:
        return jsonify({'status': 'error'}), 500


load_history()
threading.Thread(target=scheduler_loop, daemon=True).start()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"""
    Website Access Monitor
    Target: {DEFAULT_TARGET_URL}
    Dashboard: http://localhost:{port}  (set HOST=0.0.0.0 to expose on the network)
    NordVPN: {'available' if vpn_available() else 'not installed (VPN features disabled)'}
    """)
    app.run(debug=False, host=os.environ.get('HOST', '127.0.0.1'), port=port, use_reloader=False)
