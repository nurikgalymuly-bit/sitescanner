#!/usr/bin/python3
import subprocess
import os

STAGE2 = os.path.expanduser('~/Документы/sitescanner/reports/Stage_2')


def main():
    target = os.environ.get('SCAN_TARGET', '127.0.0.1')
    os.makedirs(STAGE2, exist_ok=True)
    out_base = os.path.join(STAGE2, 'nikto_scan')
    cmd = ['nikto', '-h', target, '-o', out_base, '-Format', 'txt',
           '-timeout', '3', '-maxtime', '60s']
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        pass


if __name__ == '__main__':
    main()