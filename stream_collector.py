import time
import os
from analyzer import parse_linux_content, analyze_events

def follow_file(filepath):
    """Linux 'tail -f' style generator jo nayi lines aate hi read karta hai."""
    if not os.path.exists(filepath):
        # File exist nahi karti toh create kar do
        with open(filepath, 'w') as f:
            pass

    with open(filepath, 'r') as f:
        # File ke bilkul aakhiri point par chale jao (sirf naya data lene ke liye)
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)  # Nayi line ka wait karo
                continue
            yield line