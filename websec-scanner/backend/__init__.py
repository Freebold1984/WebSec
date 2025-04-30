from pathlib import Path

# Create necessary directories
def init_directories():
    dirs = [
        'ai_engine',
        'scanners',
        'utils',
    ]
    
    for dir_name in dirs:
        Path(dir_name).mkdir(parents=True, exist_ok=True)

if __name__ == '__main__':
    init_directories()
