from typing import Dict, List, Any
from datetime import datetime
import json
from collections import defaultdict

class ReportGenerator:
    def __init__(self):
        self.severity_levels = {
            'critical': {
                'threshold': 0.8,
                'color': '#dc3545',
                'description': 'Immediate action required'
            },
            'high': {
                'threshold': 0.6,
                'color': '#fd7e14',
                'description': 'Urgent attention needed'
            },
            'medium': {
                'threshold': 0.4,
                'color': '#ffc107',
                'description': 'Should be addressed soon'
            },
            'low': {
                'threshold': 0.2,
                'color': '#28a745',
                'description': 'Monitor and review'
            },
            'info': {
                'threshold': 0,
                'color': '#17a2b8',
                'description': 'Informational finding'
            }
        }

    @staticmethod
    def create(scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive security report from scan results
        """
        generator = ReportGenerator()
        return generator._generate_report(scan_results)

    def _generate_report(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate detailed security report with findings and recommendations
        """
        report = {
            'summary': self._generate_summary(scan_results),
            'vulnerabilities': self._process_vulnerabilities(scan_results.get('vulnerabilities', [])),
            'risk_analysis': self._generate_risk_analysis(scan_results),
            'recommendations': self._generate_recommendations(scan_results),
            'technical_details': self._generate_technical_details(scan_results),
            'metadata': self._generate_metadata(scan_results)
        }
        
        return report

    def _generate_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate an executive summary of the scan results
        """
        vulnerabilities = scan_results.get('vulnerabilities', [])
        total_vulns = len(vulnerabilities)
        
        # Count vulnerabilities by severity
        severity_counts = defaultdict(int)
        for vuln in vulnerabilities:
            severity = self._determine_severity(vuln.get('risk_score', 0))
            severity_counts[severity] += 1
        
        return {
            'total_vulnerabilities': total_vulns,
            'severity_distribution': dict(severity_counts),
            'overall_risk_score': scan_results.get('risk_score', 0),
            'scan_duration': scan_results.get('duration', 0),
            'target_url': scan_results.get('target_url', ''),
            'critical_findings': severity_counts.get('critical', 0),
            'high_findings': severity_counts.get('high', 0)
        }

    def _process_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process and enrich vulnerability data
        """
        processed_vulns = []
        
        for vuln in vulnerabilities:
            severity = self._determine_severity(vuln.get('risk_score', 0))
            
            processed_vuln = {
                'id': vuln.get('id', ''),
                'title': vuln.get('type', 'Unknown Vulnerability'),
                'description': vuln.get('description', ''),
                'severity': severity,
                'risk_score': vuln.get('risk_score', 0),
                'evidence': vuln.get('evidence', ''),
                'recommendation': vuln.get('recommendation', ''),
                'technical_details': self._format_technical_details(vuln),
                'cvss_score': self._calculate_cvss_score(vuln),
                'severity_color': self.severity_levels[severity]['color'],
                'remediation_complexity': self._determine_remediation_complexity(vuln),
                'affected_components': vuln.get('affected_components', []),
                'references': self._get_vulnerability_references(vuln)
            }
            
            processed_vulns.append(processed_vuln)
        
        # Sort by risk score (descending)
        return sorted(processed_vulns, key=lambda x: x['risk_score'], reverse=True)

    def _generate_risk_analysis(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate detailed risk analysis
        """
        return {
            'overall_risk_level': self._determine_severity(scan_results.get('risk_score', 0)),
            'risk_factors': self._analyze_risk_factors(scan_results),
            'threat_landscape': self._analyze_threat_landscape(scan_results),
            'impact_analysis': self._analyze_potential_impact(scan_results),
            'risk_trends': self._analyze_risk_trends(scan_results)
        }

    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate prioritized security recommendations
        """
        recommendations = []
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Group recommendations by type
        grouped_recommendations = defaultdict(list)
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '')
            recommendation = vuln.get('recommendation', '')
            if recommendation:
                grouped_recommendations[vuln_type].append({
                    'recommendation': recommendation,
                    'risk_score': vuln.get('risk_score', 0),
                    'severity': self._determine_severity(vuln.get('risk_score', 0))
                })
        
        # Process and prioritize recommendations
        for vuln_type, recs in grouped_recommendations.items():
            # Get highest risk score for this type
            max_risk = max(r['risk_score'] for r in recs)
            
            recommendations.append({
                'category': vuln_type,
                'priority': self._determine_severity(max_risk),
                'recommendations': [r['recommendation'] for r in recs],
                'risk_score': max_risk,
                'affected_count': len(recs)
            })
        
        # Sort by risk score
        return sorted(recommendations, key=lambda x: x['risk_score'], reverse=True)

    def _generate_technical_details(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate technical details section
        """
        return {
            'scan_configuration': {
                'timestamp': scan_results.get('timestamp', datetime.now().isoformat()),
                'duration': scan_results.get('duration', 0),
                'target_url': scan_results.get('target_url', ''),
                'scan_depth': scan_results.get('scan_depth', 'normal'),
                'user_agent': scan_results.get('user_agent', '')
            },
            'technologies_detected': scan_results.get('technologies', []),
            'http_responses': self._summarize_http_responses(scan_results),
            'security_headers': self._analyze_security_headers(scan_results)
        }

    def _generate_metadata(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate scan metadata
        """
        return {
            'scan_id': scan_results.get('scan_id', ''),
            'timestamp': datetime.now().isoformat(),
            'scanner_version': '1.0.0',
            'scan_type': 'AI-Enhanced Security Scan',
            'scan_status': scan_results.get('status', 'completed')
        }

    def _determine_severity(self, risk_score: float) -> str:
        """
        Determine severity level based on risk score
        """
        for level, info in self.severity_levels.items():
            if risk_score >= info['threshold']:
                return level
        return 'info'

    def _format_technical_details(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format technical details of a vulnerability
        """
        return {
            'request': vulnerability.get('request', {}),
            'response': vulnerability.get('response', {}),
            'reproduction_steps': vulnerability.get('reproduction_steps', []),
            'affected_parameters': vulnerability.get('affected_parameters', []),
            'attack_vectors': vulnerability.get('attack_vectors', [])
        }

    def _calculate_cvss_score(self, vulnerability: Dict[str, Any]) -> float:
        """
        Calculate CVSS score based on vulnerability characteristics
        """
        # Simplified CVSS calculation
        base_score = vulnerability.get('risk_score', 0) * 10
        return round(min(10.0, base_score), 1)

    def _determine_remediation_complexity(self, vulnerability: Dict[str, Any]) -> str:
        """
        Determine the complexity of remediation
        """
        if 'remediation_complexity' in vulnerability:
            return vulnerability['remediation_complexity']
        
        # Determine based on vulnerability type and risk score
        risk_score = vulnerability.get('risk_score', 0)
        if risk_score > 0.8:
            return 'high'
        elif risk_score > 0.5:
            return 'medium'
        return 'low'

    def _get_vulnerability_references(self, vulnerability: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Get reference links for vulnerability types
        """
        vuln_type = vulnerability.get('type', '').lower()
        
        # Common reference database
        references = []
        
        if 'xss' in vuln_type:
            references.append({
                'title': 'OWASP XSS Prevention Cheat Sheet',
                'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
            })
        elif 'sql' in vuln_type:
            references.append({
                'title': 'OWASP SQL Injection Prevention Cheat Sheet',
                'url': 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
            })
        
        return references

    def _analyze_risk_factors(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze contributing risk factors
        """
        risk_factors = []
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Analyze vulnerability patterns
        vuln_types = defaultdict(int)
        for vuln in vulnerabilities:
            vuln_types[vuln.get('type', '')] += 1
        
        # Add risk factors based on findings
        for vuln_type, count in vuln_types.items():
            risk_factors.append({
                'factor': vuln_type,
                'count': count,
                'contribution': count / len(vulnerabilities) if vulnerabilities else 0
            })
        
        return sorted(risk_factors, key=lambda x: x['count'], reverse=True)

    def _analyze_threat_landscape(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze the threat landscape
        """
        return {
            'attack_surface': self._calculate_attack_surface(scan_results),
            'threat_actors': self._identify_potential_threats(scan_results),
            'vulnerability_trends': self._analyze_vulnerability_trends(scan_results)
        }

    def _analyze_potential_impact(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze potential impact of vulnerabilities
        """
        return {
            'confidentiality_impact': self._calculate_impact_score(scan_results, 'confidentiality'),
            'integrity_impact': self._calculate_impact_score(scan_results, 'integrity'),
            'availability_impact': self._calculate_impact_score(scan_results, 'availability')
        }

    def _calculate_attack_surface(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate the attack surface
        """
        return {
            'exposed_endpoints': len(scan_results.get('endpoints', [])),
            'vulnerable_parameters': len(scan_results.get('vulnerable_parameters', [])),
            'security_mechanisms': scan_results.get('security_mechanisms', [])
        }

    def _calculate_impact_score(self, scan_results: Dict[str, Any], impact_type: str) -> float:
        """
        Calculate impact score for a specific type
        """
        vulnerabilities = scan_results.get('vulnerabilities', [])
        if not vulnerabilities:
            return 0.0
        
        impact_scores = [
            vuln.get(f'{impact_type}_impact', 0)
            for vuln in vulnerabilities
        ]
        
        return sum(impact_scores) / len(impact_scores)

    def _analyze_vulnerability_trends(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze vulnerability trends
        """
        # This would typically compare with historical data
        # For now, return current scan insights
        return [{
            'type': 'current_scan',
            'total_vulnerabilities': len(scan_results.get('vulnerabilities', [])),
            'timestamp': datetime.now().isoformat()
        }]

    def _summarize_http_responses(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Summarize HTTP responses
        """
        responses = scan_results.get('http_responses', [])
        summary = defaultdict(int)
        
        for response in responses:
            status = response.get('status', 0)
            summary[str(status)] += 1
        
        return dict(summary)

    def _analyze_security_headers(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security headers
        """
        headers = scan_results.get('security_headers', {})
        analysis = {}
        
        important_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-XSS-Protection': 'Missing XSS protection header',
            'Content-Security-Policy': 'Missing Content Security Policy',
            'Strict-Transport-Security': 'Missing HSTS header'
        }
        
        for header, message in important_headers.items():
            analysis[header] = {
                'present': header in headers,
                'value': headers.get(header, ''),
                'message': message if header not in headers else 'Present'
            }
        
        return analysis
