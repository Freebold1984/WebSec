from flask import Flask, request, jsonify, send_from_directory
import os
import asyncio
import logging
from scanners.intelligent_scanner import IntelligentScanner
from ai_engine.model import AIEngine
from utils.report_generator import ReportGenerator

app = Flask(__name__, 
            static_folder='../frontend/static',
            static_url_path='/static')

ai_engine = AIEngine()

logging.basicConfig(level=logging.INFO)

@app.route('/api/scan', methods=['POST'])
def start_scan():
    try:
        data = request.get_json(force=True)
        target_url = data.get('url')
        
        if not target_url:
            return jsonify({'error': 'No target URL provided'}), 400
        
        scanner = IntelligentScanner(ai_engine)
        results = scanner.scan(target_url)
        report = ReportGenerator.create(results)
        
        return jsonify({
            'status': 'success',
            'results': results,
            'report': report
        })
    except Exception as e:
        logging.error(f"Scan failed: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/status', methods=['GET'])
def scan_status():
    scan_id = request.args.get('scan_id')
    if not scan_id:
        return jsonify({'error': 'No scan ID provided'}), 400
    
    status = IntelligentScanner.get_status(scan_id)
    return jsonify(status)

@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, '../frontend/static/img'),
        'favicon.svg',
        mimetype='image/svg+xml'
    )

if __name__ == '__main__':
    from __init__ import init_directories
    init_directories()
    app.run(debug=True, port=8000)
