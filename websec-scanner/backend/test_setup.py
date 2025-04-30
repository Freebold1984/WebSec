import sys
import importlib.util
from pathlib import Path

def check_imports():
    """Check if all required packages are installed"""
    required_packages = [
        'flask',
        'tensorflow',
        'scikit-learn',
        'numpy',
        'pandas',
        'requests',
        'aiohttp',
        'beautifulsoup4',
        'transformers'
    ]
    
    missing_packages = []
    for package in required_packages:
        if importlib.util.find_spec(package) is None:
            missing_packages.append(package)
    
    return missing_packages

def check_components():
    """Check if all component files exist and are importable"""
    components = {
        'AI Engine': [
            'ai_engine/model.py',
            'ai_engine/pattern_analyzer.py',
            'ai_engine/anomaly_detector.py',
            'ai_engine/threat_classifier.py'
        ],
        'Scanners': [
            'scanners/intelligent_scanner.py'
        ],
        'Utils': [
            'utils/report_generator.py'
        ],
        'Core': [
            'app.py'
        ]
    }
    
    missing_components = []
    base_path = Path(__file__).parent
    
    for category, files in components.items():
        for file in files:
            file_path = base_path / file
            if not file_path.exists():
                missing_components.append(f"{category}: {file}")
    
    return missing_components

def check_frontend():
    """Check if frontend files exist"""
    frontend_files = [
        '../frontend/index.html'
    ]
    
    missing_files = []
    base_path = Path(__file__).parent
    
    for file in frontend_files:
        file_path = base_path / file
        if not file_path.exists():
            missing_files.append(file)
    
    return missing_files

def main():
    """Run all checks and display results"""
    print("🔍 Running WebSec Scanner Setup Check...")
    print("\n1. Checking Required Packages:")
    missing_packages = check_imports()
    if missing_packages:
        print("❌ Missing packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\nTo install missing packages, run:")
        print(f"pip install {' '.join(missing_packages)}")
    else:
        print("✅ All required packages are installed")
    
    print("\n2. Checking Components:")
    missing_components = check_components()
    if missing_components:
        print("❌ Missing components:")
        for component in missing_components:
            print(f"   - {component}")
    else:
        print("✅ All components are present")
    
    print("\n3. Checking Frontend:")
    missing_frontend = check_frontend()
    if missing_frontend:
        print("❌ Missing frontend files:")
        for file in missing_frontend:
            print(f"   - {file}")
    else:
        print("✅ Frontend files are present")
    
    if not (missing_packages or missing_components or missing_frontend):
        print("\n✨ Setup check completed successfully! The system is ready to run.")
        print("\nTo start the scanner:")
        print("1. Navigate to the backend directory:")
        print("   cd backend")
        print("2. Run the application:")
        print("   python app.py")
        print("3. Open your browser and visit:")
        print("   http://localhost:5000")
    else:
        print("\n⚠️ Please address the issues above before running the system.")

if __name__ == "__main__":
    main()
