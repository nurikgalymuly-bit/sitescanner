#!/usr/bin/python3
import subprocess
import shlex
import os

STAGE2 = os.path.expanduser('~/Документы/sitescanner/reports/Stage_2')


def main():
    target = os.environ.get('SCAN_TARGET', '127.0.0.1')
    os.makedirs(STAGE2, exist_ok=True)
    out_xml = os.path.join(STAGE2, 'vuln_scan.xml')
    nmap_cmd = f"/usr/bin/nmap --privileged {target} -n -Pn --script vuln -T4 -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()


if __name__ == '__main__':
    main()