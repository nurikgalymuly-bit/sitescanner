#!/usr/bin/python3
import requests
import json
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

STAGE2 = os.path.expanduser('~/Документы/sitescanner/reports/Stage_2')

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Content-Security-Policy',
    'Referrer-Policy',
    'Permissions-Policy',
]


def main():
    target = os.environ.get('SCAN_TARGET', '127.0.0.1')
    result = {'target': target, 'headers': {}, 'missing': [], 'error': None}

    for scheme in ('https', 'http'):
        try:
            resp = requests.get(f'{scheme}://{target}', timeout=8, verify=False)
            for h in SECURITY_HEADERS:
                result['headers'][h] = resp.headers.get(h)
            result['missing'] = [h for h in SECURITY_HEADERS if not resp.headers.get(h)]
            result['status_code'] = resp.status_code
            result['scheme'] = scheme
            result['error'] = None
            break
        except requests.RequestException as e:
            result['error'] = str(e)

    os.makedirs(STAGE2, exist_ok=True)
    out_path = os.path.join(STAGE2, 'headers_check.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)


if __name__ == '__main__':
    main()