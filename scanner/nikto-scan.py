#!/usr/bin/python3
import subprocess
import os

STAGE2 = os.path.expanduser('~/Документы/sitescanner/reports/Stage_2')


def main():
    target = os.environ.get('SCAN_TARGET', '127.0.0.1')
    os.makedirs(STAGE2, exist_ok=True)
    out_path = os.path.join(STAGE2, 'nikto_scan.txt')
    cmd = ['nikto', '-h', target, '-o', out_path, '-Format', 'txt', '-timeout', '10']
    subprocess.run(cmd, capture_output=True, text=True, timeout=180)


if __name__ == '__main__':
    main()