# WebSec Project

This repository contains the WebSec project, including backend and frontend components, as well as the Burp AI extension.

## Project Structure

- `websec-scanner/`: Main project directory containing backend and frontend code.
- `burp-ai-extension/`: Burp Suite AI extension code and dependencies.

## Setup

### Backend

1. Create a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

2. Install backend dependencies:

```bash
pip install -r websec-scanner/backend/requirements.txt
```

3. Set required environment variables, for example:

```bash
export HF_API_TOKEN="your_huggingface_api_token"
```

### Frontend

1. Navigate to the frontend directory:

```bash
cd websec-scanner/frontend
```

2. Install frontend dependencies:

```bash
npm install
```

3. Run the frontend development server:

```bash
npm start
```

## Usage

- Run backend services as needed.
- Use the frontend to interact with the WebSec scanner.
- Refer to the `burp-ai-extension` directory for Burp Suite AI extension details.

## Notes

- Do not commit sensitive information such as API tokens.
- Use environment variables to manage secrets securely.

## License

Specify your project license here.
