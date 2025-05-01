from burp import IBurpExtender, IHttpListener # type: ignore
from java.io import PrintWriter # type: ignore
import os
import requests

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._callbacks.setExtensionName("AI Vulnerability Analyzer")
        self._callbacks.registerHttpListener(self)

        self.hf_token = os.getenv("HF_API_TOKEN")
        if not self.hf_token:
            self._stderr.println("HF_API_TOKEN environment variable not set!")
        self.pattern_url = "https://api-inference.huggingface.co/models/microsoft/codebert-base"
        self.anomaly_url = "https://api-inference.huggingface.co/models/microsoft/anomaly-detector"
        self.threat_url = "https://api-inference.huggingface.co/models/distilbert-base-uncased"
        self.headers = {"Authorization": "Bearer " + self.hf_token}

        self._stdout.println("AI Vulnerability Analyzer extension loaded")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request = messageInfo.getRequest()
            analysis = self.analyze_request(request)
            self._stdout.println("AI Analysis: %s" % str(analysis))

    def analyze_request(self, request):
        try:
            request_info = self._helpers.analyzeRequest(request)
            headers = request_info.getHeaders()
            body_offset = request_info.getBodyOffset()
            body = request[body_offset:]
            text = self._prepare_text(headers, body)
            pattern_score = self._call_hf_api(self.pattern_url, text)
            anomaly_score = self._call_hf_api(self.anomaly_url, text)
            threat_level = self._call_hf_api(self.threat_url, text, weighted=True)
            risk_score = self._calculate_risk_score(pattern_score, anomaly_score, threat_level)
            return {
                'pattern_score': pattern_score,
                'anomaly_score': anomaly_score,
                'threat_level': threat_level,
                'risk_score': risk_score
            }
        except Exception as e:
            self._stderr.println(f"Error analyzing request: {str(e)}")
            return {}

    def _call_hf_api(self, url, text, weighted=False):
        try:
            response = requests.post(url, headers=self.headers, json={"inputs": text})
            response.raise_for_status()
            result = response.json()
            if weighted and isinstance(result, list) and all('score' in item for item in result):
                scores = [item['score'] for item in result]
                weights = [0.1, 0.3, 0.6, 0.9]
                return sum(s * w for s, w in zip(scores, weights))
            if isinstance(result, list) and 'score' in result[0]:
                return float(result[0]['score'])
            return 0.0
        except Exception as e:
            self._stderr.println(f"Error calling Hugging Face API: {str(e)}")
            return 0.0

    def _prepare_text(self, headers, body):
        headers_text = " ".join(str(h) for h in headers)
        body_text = body.tostring() if hasattr(body, 'tostring') else str(body)
        return headers_text + " " + body_text

    def _calculate_risk_score(self, pattern_score, anomaly_score, threat_level):
        weights = {'pattern': 0.3, 'anomaly': 0.4, 'threat': 0.3}
        return min(1.0,
                   pattern_score * weights['pattern'] +
                   anomaly_score * weights['anomaly'] +
                   threat_level * weights['threat'])
