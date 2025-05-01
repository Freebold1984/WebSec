import os
import requests
import logging

def test_model_integration():
    hf_token = os.getenv("HF_API_TOKEN")
    endpoint_url = os.getenv("HACKERONE_BERT_ENDPOINT_URL")

    if not hf_token or not endpoint_url:
        print("HF_API_TOKEN or HACKERONE_BERT_ENDPOINT_URL environment variables not set.")
        return

    headers = {"Authorization": f"Bearer {hf_token}"}
    sample_response_content = """
    <html>
    <body>
    <script>alert("xss")</script>
    </body>
    </html>
    """

    payload = {
        "inputs": {
            "question": "Is this response vulnerable or contains security issues?",
            "context": sample_response_content
        }
    }

    try:
        logging.basicConfig(level=logging.DEBUG)
        logging.info(f"Sending payload to model endpoint: {payload}")
        response = requests.post(endpoint_url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        result = response.json()
        logging.info(f"Received response from model endpoint: {result}")
        print("Model response:", result)
    except Exception as e:
        logging.error(f"Error calling model endpoint: {e}")

if __name__ == "__main__":
    test_model_integration()
