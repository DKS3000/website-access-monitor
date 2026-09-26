#!/usr/bin/env python3
import os
import json
import time
import subprocess
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request
import requests

app = Flask(__name__)
app.secret_key = 'website-access-monitor-secret-key-2026'

monitoring_status = {
    'running': False,
    'current_country': 'US',
    'target_url': 'https://dgft.co.in',
    'current_result': None,
    'last_updated': None,
    'results_history': [],
    'vpn_connected': False,
    'current_vpn_country': None,
    'attempts': 0,
    'success': False
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

def check_vpn_status():
    """Check if NordVPN is connected"""
    try:
        result = subprocess.run(['nordvpn', 'status'], capture_output=True, text=True, timeout=5)
        output = result.stdout.lower()
        return 'connected' in output
    except:
        return False

def get_vpn_country():
    """Get current VPN country"""
    try:
        result = subprocess.run(['nordvpn', 'status'], capture_output=True, text=True, timeout=5)
        lines = result.stdout.split('\n')
        for line in lines:
            if 'country' in line.lower():
                return line.split(':')[1].strip() if ':' in line else None
        return None
    except:
        return None

def connect_vpn(country_code):
    """Connect to NordVPN country"""
    try:
        print(f"Connecting to NordVPN: {country_code}")
        result = subprocess.run(
            ['nordvpn', 'connect', country_code],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            time.sleep(3)  # Wait for connection to stabilize
            return True
        return False
    except Exception as e:
        print(f"Error connecting VPN: {e}")
        return False

def run_monitor(target_url):
    """Run single website test"""
    try:
        config = {
            'routes': [
                {'name': 'direct', 'type': 'direct', 'description': 'Direct connection (through VPN if active)'}
            ]
        }
        
        with open('/tmp/monitor_config.json', 'w') as f:
            json.dump(config, f)
        
        result = subprocess.run(
            ['python', 'monitor.py', '--target', target_url, '--config', '/tmp/monitor_config.json'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            return {'error': result.stderr}
    except Exception as e:
        return {'error': str(e)}

def monitoring_loop_until_success():
    """Keep testing until page opens successfully"""
    monitoring_status['attempts'] = 0
    monitoring_status['success'] = False
    max_attempts = 30
    
    while monitoring_status['running'] and monitoring_status['attempts'] < max_attempts:
        monitoring_status['attempts'] += 1
        print(f"Attempt {monitoring_status['attempts']}/{max_attempts} - Testing {monitoring_status['target_url']}")
        
        result = run_monitor(monitoring_status['target_url'])
        monitoring_status['current_result'] = result
        monitoring_status['last_updated'] = datetime.now().isoformat()
        
        # Check if successful
        if result.get('results') and len(result['results']) > 0:
            first_result = result['results'][0]
            if first_result.get('status') == 'success' and first_result.get('http_status') == 200:
                monitoring_status['success'] = True
                monitoring_status['running'] = False
                print(f"✓ SUCCESS! Page opened on attempt {monitoring_status['attempts']}")
                break
        
        # Store in history
        monitoring_status['results_history'].append({
            'timestamp': monitoring_status['last_updated'],
            'country': monitoring_status['current_country'],
            'attempt': monitoring_status['attempts'],
            'result': result
        })
        
        if len(monitoring_status['results_history']) > 100:
            monitoring_status['results_history'].pop(0)
        
        # Wait 2 seconds before retry
        if not monitoring_status['success']:
            time.sleep(2)

@app.route('/')
def index():
    return render_template('dashboard_enhanced.html', vpn_countries=VPN_COUNTRIES)

@app.route('/api/status')
def get_status():
    vpn_status = check_vpn_status()
    monitoring_status['vpn_connected'] = vpn_status
    
    return jsonify({
        'running': monitoring_status['running'],
        'country': monitoring_status['current_country'],
        'target_url': monitoring_status['target_url'],
        'last_updated': monitoring_status['last_updated'],
        'current_result': monitoring_status['current_result'],
        'vpn_connected': vpn_status,
        'vpn_country': get_vpn_country(),
        'attempts': monitoring_status['attempts'],
        'success': monitoring_status['success']
    })

@app.route('/api/start', methods=['POST'])
def start_testing():
    """Start VPN connection and test until success"""
    if monitoring_status['running']:
        return jsonify({'status': 'already running'})
    
    data = request.json or {}
    country = data.get('country', 'US')
    target_url = data.get('target_url', 'https://dgft.co.in')
    
    monitoring_status['running'] = True
    monitoring_status['current_country'] = country
    monitoring_status['target_url'] = target_url
    monitoring_status['attempts'] = 0
    monitoring_status['success'] = False
    
    # Connect VPN in background thread
    def connect_and_test():
        country_code = VPN_COUNTRIES.get(country, 'us')
        
        # Connect to VPN
        if connect_vpn(country_code):
            monitoring_status['vpn_connected'] = True
            time.sleep(2)
        
        # Start testing loop
        monitoring_loop_until_success()
    
    thread = threading.Thread(target=connect_and_test, daemon=True)
    thread.start()
    
    return jsonify({'status': 'started', 'country': country})

@app.route('/api/stop', methods=['POST'])
def stop_testing():
    """Stop testing"""
    monitoring_status['running'] = False
    return jsonify({'status': 'stopped'})

@app.route('/api/history')
def get_history():
    return jsonify(monitoring_status['results_history'])

@app.route('/api/vpn/disconnect', methods=['POST'])
def disconnect_vpn():
    """Disconnect VPN"""
    try:
        subprocess.run(['nordvpn', 'disconnect'], capture_output=True, timeout=10)
        monitoring_status['vpn_connected'] = False
        return jsonify({'status': 'disconnected'})
    except:
        return jsonify({'status': 'error'}), 500

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    print("""

    ╔════════════════════════════════════════════════════╗
    ║   Website Access Monitor - NordVPN Edition        ║
    ║   Starting on http://localhost:5000               ║
    ║   Open http://YOUR_IP:5000 in your browser        ║
    ║   Make sure NordVPN is installed: sudo apt install nordvpn
    ╚════════════════════════════════════════════════════╝

    """)
    
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
