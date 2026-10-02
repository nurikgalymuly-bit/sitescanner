#!/usr/bin/env python3
import sys, subprocess, os
import logging

logging.basicConfig(level=logging.INFO)

target = os.environ.get('SCAN_TARGET', sys.argv[1] if len(sys.argv) > 1 else '')
out_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser('~/Документы/sitescanner/reports/Stage_2')
out_file = os.path.join(out_dir, 'whatweb_scan.txt')

if not target:
    sys.exit(1)

try:
    # Исключаем флаг -q, чтобы точно получить вывод, и отключаем цвета
    res = subprocess.run(['whatweb', '--color=never', '-a', '1', target], capture_output=True, text=True, timeout=60)
    
    out_text = res.stdout.strip()
    if not out_text:
        out_text = res.stderr.strip()
        
    if not out_text:
        out_text = "WhatWeb не смог определить технологии (пустой ответ)."
        
    with open(out_file, 'w') as f:
        f.write(out_text)
except FileNotFoundError:
    with open(out_file, 'w') as f:
        f.write("WhatWeb не установлен в системе.")
except Exception as e:
    with open(out_file, 'w') as f:
        f.write(f"Ошибка WhatWeb: {str(e)}")

sys.exit(0)
