# Burp Suite AI Extension

This project contains a Burp Suite extension built with Python using the Montoya API. It integrates the AIEngine for real-time security analysis of HTTP requests and responses.

## Features

- Uses Montoya API for Burp Suite extension development in Python
- Integrates AIEngine for pattern analysis, anomaly detection, and threat classification
- Designed to work alongside the standalone AIEngine service or as a self-contained extension

## Setup

1. Ensure you have Python 3.8+ installed.
2. Install Montoya SDK and dependencies.
3. Configure your Hugging Face API token as an environment variable `HF_API_TOKEN`.
4. Build and load the extension in Burp Suite.

## Next Steps

- Implement extension logic to intercept HTTP traffic.
- Call AIEngine methods to analyze traffic.
- Display analysis results in Burp Suite UI.
