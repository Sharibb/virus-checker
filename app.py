from flask import Flask, render_template, request, jsonify
import os
import yara
import requests

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
YARA_RULES_FOLDER = 'yara_rules'
VIRUSTOTAL_API_KEY = 'YOUR_API_KEY'  # Replace with your VirusTotal API key

# Ensure upload directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Function to load YARA rules from files in a folder
def load_yara_rules(folder_path):
    rule_files = {f: os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith('.rule')}
    print(f"Loading YARA rules from: {rule_files}")
    rules = yara.compile(filepaths=rule_files)
    return rules

# Function to scan file with loaded YARA rules
def scan_with_yara(file_path):
    try:
        print(f"Scanning file: {file_path}")
        rules = load_yara_rules(YARA_RULES_FOLDER)
        matches = rules.match(file_path, externals={"filepath": file_path})
        print(f"YARA matches: {matches}")
        return [str(match) for match in matches]
    except yara.Error as e:
        error_message = f"YARA error: {e}"
        print(error_message)
        return [error_message]

# Function to scan file with VirusTotal API v2
def scan_with_virustotal(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': VIRUSTOTAL_API_KEY}
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    response = requests.post(url, params=params, files=files)
    return response.json()

# Function to get VirusTotal report using API v2
def get_virustotal_report(scan_id):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': scan_id}
    response = requests.get(url, params=params)
    return response.json()

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if file:
            filename = file.filename
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            
            # Scan file with YARA rules
            yara_results = scan_with_yara(file_path)
            
            # Scan file with VirusTotal API v2
            scan_response = scan_with_virustotal(file_path)
            if 'scan_id' in scan_response:
                scan_id = scan_response['scan_id']
                return jsonify({'scan_id': scan_id, 'yara_results': yara_results})
            else:
                return jsonify({'error': 'VirusTotal scan failed'}), 500
    
    return render_template('index.html')

@app.route('/check_scan/<scan_id>')
def check_scan(scan_id):
    report = get_virustotal_report(scan_id)
    if report.get('response_code') == 1:
        return jsonify(report)
    elif report.get('response_code') == -2:
        return jsonify({'response_code': -2, 'error': 'Scan report not ready'}), 202
    else:
        return jsonify({'response_code': -1, 'error': 'Scan not found or other error'}), 404

@app.route('/results/<scan_id>')
def results(scan_id):
    report = get_virustotal_report(scan_id)
    yara_results = request.args.getlist('yara_results')
    return render_template('results.html', virustotal_results=report, yara_results=yara_results)

if __name__ == '__main__':
    app.run()
