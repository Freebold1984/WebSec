
from typing import Dict, List, Any
import logging
from datetime import datetime
import requests
from bs4 import BeautifulSoup

class IntelligentScanner:
    def __init__(self, ai_engine):
        self.ai_engine = ai_engine
        self.active_scans = {}
        self.logger = logging.getLogger(__name__)
        
    def scan(self, target_url: str) -> Dict[str, Any]:
        """
        Perform an intelligent security scan of the target URL
        """
        scan_id = self._generate_scan_id()
        self.active_scans[scan_id] = {
            'status': 'running',
            'start_time': datetime.now(),
            'target_url': target_url,
            'findings': []
        }
        
        try:
            # Initial reconnaissance
            recon_data = self._perform_reconnaissance(target_url)
            
            # AI-powered analysis of the target
            analysis_result = self.ai_engine.analyze_request({
                'url': target_url,
                'recon_data': recon_data
            })
            
            # Generate intelligent payloads based on analysis
            payloads = self.ai_engine.generate_payloads({
                'url': target_url,
                'analysis': analysis_result
            })
            
            # Perform vulnerability scanning with intelligent payloads
            vulnerabilities = self._scan_vulnerabilities(target_url, payloads)
            
            # Remove static example vulnerabilities to avoid repeated results
            # example_vulns = [
            #     {
            #         'type': 'XSS',
            #         'risk_score': 0.85,
            #         'evidence': '<script>alert("XSS")</script> was reflected in response',
            #         'recommendation': 'Implement proper input validation and output encoding'
            #     },
            #     {
            #         'type': 'SQL Injection',
            #         'risk_score': 0.75,
            #         'evidence': "SQL error detected: 'mysql_error' in response",
            #         'recommendation': 'Use parameterized queries and input validation'
            #     }
            # ]
            
            # vulnerabilities.extend(example_vulns)
            
            # Update scan status
            self.active_scans[scan_id].update({
                'status': 'completed',
                'end_time': datetime.now(),
                'findings': vulnerabilities
            })
            
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'vulnerabilities': vulnerabilities,
                'risk_score': analysis_result.get('risk_score', 0.65),
                'technologies': ['Python', 'Flask', 'MySQL'],  # Example detected technologies
            }
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            self.active_scans[scan_id]['status'] = 'failed'
            raise
    
    def _perform_reconnaissance(self, url: str) -> Dict[str, Any]:
        """
        Perform initial reconnaissance of the target
        """
        try:
            # Get initial response
            response = requests.get(url, timeout=10)
            headers = dict(response.headers)
            content = response.text
            
            # Parse HTML content
            soup = BeautifulSoup(content, 'html.parser')
            
            return {
                'status': response.status_code,
                'headers': headers,
                'content': content,
                'server_info': headers.get('Server'),
                'technologies': self._detect_technologies(headers, content)
            }
        except Exception as e:
            self.logger.error(f"Reconnaissance failed: {str(e)}")
            raise
    
    def _scan_vulnerabilities(self, url: str, payloads: List[str]) -> List[Dict[str, Any]]:
        """
        Perform vulnerability scanning using intelligent payloads
        """
        vulnerabilities = []
        
        for payload in payloads:
            try:
                # Prepare payload injection
                method = payload.get('method', 'GET')
                content = payload.get('content', '')
                headers = payload.get('headers', {})
                
                # Inject payload in URL query parameters for GET requests
                if method.upper() == 'GET':
                    if '?' in url:
                        test_url = f"{url}&input={content}"
                    else:
                        test_url = f"{url}?input={content}"
                    response = requests.get(test_url, headers=headers, timeout=10)
                else:
                    # For POST or other methods, send payload in data
                    data = payload.get('data')
                    if data is None:
                        data = {'input': content}
                    response = requests.request(method, url, data=data, headers=headers, timeout=10)
                
                result = {
                    'status': response.status_code,
                    'headers': dict(response.headers),
                    'content': response.text
                }
                
                # Analyze response with AI
                analysis = self.ai_engine.analyze_response(result)
                
                if analysis.get('risk_score', 0) > 0.7:  # High risk threshold
                    vulnerabilities.append({
                        'type': payload.get('type', 'Unknown'),
                        'payload': content,
                        'risk_score': analysis.get('risk_score', 0),
                        'evidence': result,
                        'recommendation': self._generate_recommendation(payload.get('type', ''))
                    })
            
            except Exception as e:
                self.logger.error(f"Payload testing failed: {str(e)}")
                continue
        
        return vulnerabilities
    
    def _test_payload(self, url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test a specific payload against the target
        """
        try:
            method = payload.get('method', 'GET')
            data = payload.get('data')
            headers = payload.get('headers', {})
            
            # Inject payload in URL query parameters for GET requests
            if method.upper() == 'GET':
                content = payload.get('content', '')
                if '?' in url:
                    test_url = f"{url}&input={content}"
                else:
                    test_url = f"{url}?input={content}"
                response = requests.get(test_url, headers=headers, timeout=10)
            else:
                if data is None:
                    data = {'input': payload.get('content', '')}
                response = requests.request(method, url, data=data, headers=headers, timeout=10)
            
            return {
                'status': response.status_code,
                'headers': dict(response.headers),
                'content': response.text
            }
        except Exception as e:
            self.logger.error(f"Payload test failed: {str(e)}")
            raise
    
    def _detect_technologies(self, headers: Dict[str, str], content: str) -> List[str]:
        """
        Detect technologies used by the target application
        """
        technologies = []
        
        # Check headers for technology indicators
        if 'X-Powered-By' in headers:
            technologies.append(headers['X-Powered-By'])
        
        # Check for common technology signatures in content
        tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes'],
            'jQuery': ['jquery'],
            'React': ['react', 'reactjs'],
            'Angular': ['ng-', 'angular'],
            'Vue.js': ['vue', 'vuejs']
        }
        
        for tech, signatures in tech_signatures.items():
            if any(sig in content.lower() for sig in signatures):
                technologies.append(tech)
        
        return technologies
    
    def _generate_recommendation(self, vulnerability_type: str) -> str:
        """
        Generate security recommendations based on vulnerability type
        """
        recommendations = {
            'xss': 'Implement proper input validation and output encoding',
            'sql_injection': 'Use parameterized queries or ORM',
            'csrf': 'Implement CSRF tokens and validate them server-side',
            'open_redirect': 'Validate and sanitize all redirect URLs',
            'file_upload': 'Implement strict file type validation and scanning'
        }
        
        return recommendations.get(
            vulnerability_type.lower(),
            'Review security best practices for this type of vulnerability'
        )
    
    def _generate_scan_id(self) -> str:
        """
        Generate a unique scan identifier
        """
        import uuid
        return str(uuid.uuid4())
    
    @classmethod
    def get_status(cls, scan_id: str) -> Dict[str, Any]:
        """
        Get the current status of a scan
        """
        if not hasattr(cls, 'active_scans'):
            cls.active_scans = {}
            
        if scan_id not in cls.active_scans:
            return {'error': 'Scan not found'}
        
        return cls.active_scans[scan_id]
