from flask import Flask, request, jsonify, send_from_directory
import os
import asyncio
from scanners.intelligent_scanner import IntelligentScanner
from ai_engine.model import AIEngine
from utils.report_generator import ReportGenerator

# Initialize Flask app with static files configuration
app = Flask(__name__, 
            static_folder='../frontend/static',
            static_url_path='/static')

# Initialize AI engine
ai_engine = AIEngine()

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new security scan with AI-powered analysis"""
    data = request.get_json()
    target_url = data.get('url')
    
    if not target_url:
        return jsonify({'error': 'No target URL provided'}), 400
    
    # Initialize scanner with AI engine
    scanner = IntelligentScanner(ai_engine)
    
    try:
        # Start the scan
        results = scanner.scan(target_url)
        
        # Generate report
        report = ReportGenerator.create(results)
        
        return jsonify({
            'status': 'success',
            'results': results,
            'report': report
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/status', methods=['GET'])
def scan_status():
    """Get the current scan status"""
    scan_id = request.args.get('scan_id')
    if not scan_id:
        return jsonify({'error': 'No scan ID provided'}), 400
    
    # Get scan status
    status = IntelligentScanner.get_status(scan_id)
    return jsonify(status)

@app.route('/')
def index():
    """Serve the main frontend page"""
    return send_from_directory('../frontend', 'index.html')

@app.route('/favicon.ico')
def favicon():
    """Serve the favicon"""
    return send_from_directory(
        os.path.join(app.root_path, '../frontend/static/img'),
        'favicon.svg',
        mimetype='image/svg+xml'
    )

if __name__ == '__main__':
    # Initialize directories
    from __init__ import init_directories
    init_directories()
    
    # Run the application
    app.run(debug=True, port=8000)
