from flask import Flask, request, jsonify, send_from_directory
import subprocess
import json
import os
from datetime import datetime
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    target = data.get('target')
    threads = data.get('threads', 5)
    timeout = data.get('timeout', 10)
    depth = data.get('depth', 2)
    
    if not target:
        return jsonify({'error': 'Target URL is required'}), 400
    
    # Run the BlackWidow scanner
    try:
        cmd = ['python', 'blackwidow.py', target, 
               '--threads', str(threads), 
               '--timeout', str(timeout), 
               '--depth', str(depth)]
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        # Find the latest report file
        report_files = [f for f in os.listdir('.') if f.startswith('security_report_') and f.endswith('.html')]
        report_files.sort(reverse=True)
        
        if not report_files:
            return jsonify({'error': 'No report generated'}), 500
        
        latest_report = report_files[0]
        
        # Parse the log file to extract results
        log_files = [f for f in os.listdir('.') if f.startswith('scan_') and f.endswith('.log')]
        log_files.sort(reverse=True)
        
        # Try to use the API to get structured results
        try:
            api_cmd = ['python', 'blackwidow_api.py', target, 
                      '--threads', str(threads), 
                      '--timeout', str(timeout), 
                      '--depth', str(depth),
                      '--json']
            
            api_process = subprocess.Popen(api_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            api_stdout, api_stderr = api_process.communicate()
            
            # Parse JSON output from the API
            results = json.loads(api_stdout.decode('utf-8'))
            results['report_file'] = latest_report
            
            if log_files:
                results['log_file'] = log_files[0]
                
            return jsonify(results)
            
        except Exception as e:
            # Fallback to basic results if API fails
            results = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'report_file': latest_report,
                'vulnerabilities': []
            }
            
            if log_files:
                results['log_file'] = log_files[0]
            
            return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports', methods=['GET'])
def list_reports():
    report_files = [f for f in os.listdir('.') if f.startswith('security_report_') and f.endswith('.html')]
    report_files.sort(reverse=True)
    
    reports = []
    for report in report_files:
        timestamp = report.replace('security_report_', '').replace('.html', '')
        try:
            date = datetime.strptime(timestamp, '%Y%m%d_%H%M%S')
            reports.append({
                'filename': report,
                'timestamp': date.isoformat()
            })
        except:
            continue
    
    return jsonify(reports)

@app.route('/reports/<path:filename>')
def serve_report(filename):
    return send_from_directory('.', filename)

if __name__ == '__main__':
    app.run(debug=True, port=5000)