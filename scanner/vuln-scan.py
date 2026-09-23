#!/usr/bin/python3
import subprocess
import shlex
import os
import xml.etree.ElementTree as ET

STAGE2 = os.path.expanduser('~/Документы/sitescanner/reports/Stage_2')


def get_open_ports():
    path = os.path.join(STAGE2, 'top_1000_portscan.xml')
    if not os.path.exists(path):
        return None
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return None
    ports = []
    for host in root.findall('host'):
        ports_el = host.find('ports')
        if ports_el is None:
            continue
        for port in ports_el.findall('port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                ports.append(port.get('portid'))
    return ','.join(ports) if ports else None


def main():
    target = os.environ.get('SCAN_TARGET', '127.0.0.1')
    os.makedirs(STAGE2, exist_ok=True)
    out_xml = os.path.join(STAGE2, 'vuln_scan.xml')

    ports = get_open_ports()
    port_flag = f"-p {ports}" if ports else "--top-ports 20"

    nmap_cmd = f"/usr/bin/nmap --privileged {target} {port_flag} -n -Pn --script vuln -T5 --host-timeout 90s -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()


if __name__ == '__main__':
    main()