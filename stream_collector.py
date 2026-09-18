import time
import os

def follow_file(filepath):
    """Windows-safe file watcher using byte offset tracking."""
    if not os.path.exists(filepath):
        with open(filepath, 'w') as f:
            pass

    # Start tracking from the end of the file
    last_pos = os.path.getsize(filepath)

    while True:
        current_size = os.path.getsize(filepath)

        if current_size > last_pos:
            # File ko open karke sirf naya chunk read karo, fir instantly CLOSE kar do
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                last_pos = f.tell()

            for line in new_lines:
                if line.strip():
                    yield line.strip()
        elif current_size < last_pos:
            # Agar file truncate ya clear ho gayi ho
            last_pos = current_size

        time.sleep(0.5)