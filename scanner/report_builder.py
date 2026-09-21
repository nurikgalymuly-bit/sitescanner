#!/usr/bin/python3
import xml.etree.ElementTree as ET
import json
import os

STAGE1 = os.path.expanduser('~/Документы/sitescanner/reports/Stage_1')
STAGE2 = os.path.expanduser('~/Документы/sitescanner/reports/Stage_2')


def safe_parse(path):
    if not os.path.exists(path):
        return None
    try:
        return ET.parse(path).getroot()
    except ET.ParseError:
        return None


def get_live_hosts():
    hosts = {}
    for fname in ['icmp_echo_host_discovery.xml', 'icmp_netmask_host_discovery.xml',
                  'icmp_timestamp_host_discovery.xml', 'tcp_syn_host_discovery.xml']:
        root = safe_parse(os.path.join(STAGE1, fname))
        if root is None:
            continue
        for host in root.findall('host'):
            state = host.find('status').get('state')
            if state == 'up':
                addr = host.find('address').get('addr')
                hostname_el = host.find('hostnames/hostname')
                name = hostname_el.get('name') if hostname_el is not None else None
                hosts[addr] = name
    return hosts


def get_open_ports(xml_path):
    root = safe_parse(xml_path)
    if root is None:
        return {}
    result = {}
    for host in root.findall('host'):
        addr = host.find('address').get('addr')
        ports_el = host.find('ports')
        if ports_el is None:
            continue
        open_ports = []
        for port in ports_el.findall('port'):
            state = port.find('state').get('state')
            if state != 'open':
                continue
            portid = port.get('portid')
            proto = port.get('protocol')
            service_el = port.find('service')
            service = service_el.get('name') if service_el is not None else '?'
            open_ports.append({'port': int(portid), 'protocol': proto, 'service': service})
        if open_ports:
            open_ports.sort(key=lambda p: p['port'])
            result[addr] = open_ports
    return result


def get_os_matches():
    root = safe_parse(os.path.join(STAGE1, 'osdetection.xml'))
    if root is None:
        return {}
    result = {}
    for host in root.findall('host'):
        addr = host.find('address').get('addr')
        os_el = host.find('os')
        matches = []
        if os_el is not None:
            for match in os_el.findall('osmatch')[:3]:
                matches.append({
                    'name': match.get('name'),
                    'accuracy': int(match.get('accuracy'))
                })
        matches.sort(key=lambda m: m['accuracy'], reverse=True)
        result[addr] = matches
    return result


def get_services():
    result = {}
    for fname in os.listdir(STAGE2):
        if not fname.endswith('_services.xml'):
            continue
        addr = fname.replace('_services.xml', '')
        root = safe_parse(os.path.join(STAGE2, fname))
        if root is None:
            continue
        services = []
        for host in root.findall('host'):
            for port in host.find('ports').findall('port'):
                if port.find('state').get('state') != 'open':
                    continue
                portid = port.get('portid')
                service_el = port.find('service')
                name = service_el.get('name', '?') if service_el is not None else '?'
                services.append({'port': int(portid), 'name': name})
        services.sort(key=lambda s: s['port'])
        result[addr] = services
    return result


def get_ssl_certs():
    result = {}
    for fname in os.listdir(STAGE2):
        if not fname.endswith('_ssl_certs.xml'):
            continue
        addr = fname.replace('_ssl_certs.xml', '')
        root = safe_parse(os.path.join(STAGE2, fname))
        if root is None:
            continue
        raw_certs = []
        for host in root.findall('host'):
            for port in host.find('ports').findall('port'):
                portid = port.get('portid')
                for script in port.findall("script[@id='ssl-cert']"):
                    output = script.get('output', '').strip()
                    subject = None
                    issuer = None
                    valid_after = None
                    for line in output.splitlines():
                        line = line.strip()
                        if line.startswith('Subject:') and subject is None:
                            subject = line.replace('Subject:', '').strip()
                        elif line.startswith('Issuer:') and issuer is None:
                            issuer = line.split('/')[0].replace('Issuer:', '').strip()
                        elif line.startswith('Not valid after:'):
                            valid_after = line.replace('Not valid after:', '').strip()
                    raw_certs.append({
                        'port': int(portid),
                        'subject': subject or 'не определено',
                        'issuer': issuer or 'не определено',
                        'valid_after': valid_after or 'не определено',
                    })
        grouped = {}
        for c in raw_certs:
            key = (c['subject'], c['issuer'], c['valid_after'])
            grouped.setdefault(key, []).append(c['port'])
        certs = []
        for (subject, issuer, valid_after), ports in grouped.items():
            mismatch = addr not in subject and not subject.endswith(addr)
            certs.append({
                'ports': sorted(ports),
                'subject': subject,
                'issuer': issuer,
                'valid_after': valid_after,
                'domain_mismatch': mismatch,
            })
        result[addr] = certs
    return result


def get_ssl_ciphers():
    result = {}
    for fname in os.listdir(STAGE2):
        if not fname.endswith('_ssl_ciphers.xml'):
            continue
        addr = fname.replace('_ssl_ciphers.xml', '')
        root = safe_parse(os.path.join(STAGE2, fname))
        if root is None:
            continue
        ciphers = []
        for host in root.findall('host'):
            for port in host.find('ports').findall('port'):
                portid = port.get('portid')
                for script in port.findall("script[@id='ssl-enum-ciphers']"):
                    output = script.get('output', '').strip()
                    protocols = []
                    strength = None
                    for line in output.splitlines():
                        line = line.strip()
                        if line.startswith('TLSv') or line.startswith('SSLv'):
                            protocols.append(line.rstrip(':'))
                        elif line.startswith('least strength:'):
                            strength = line.replace('least strength:', '').strip()
                    ciphers.append({
                        'port': int(portid),
                        'protocols': protocols,
                        'grade': strength,
                    })
        ciphers.sort(key=lambda c: c['port'])
        result[addr] = ciphers
    return result


def get_headers_check():
    path = os.path.join(STAGE2, 'headers_check.json')
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def get_vuln_findings():
    root = safe_parse(os.path.join(STAGE2, 'vuln_scan.xml'))
    if root is None:
        return []
    findings = []
    for host in root.findall('host'):
        ports_el = host.find('ports')
        if ports_el is None:
            continue
        for port in ports_el.findall('port'):
            portid = port.get('portid')
            for script in port.findall('script'):
                output = script.get('output', '').strip()
                if not output or 'not vulnerable' in output.lower() or output.upper().startswith('ERROR'):
                    continue
                findings.append({
                    'port': int(portid),
                    'script': script.get('id'),
                    'output': output,
                })
    return findings


def get_nikto_findings():
    path = os.path.join(STAGE2, 'nikto_scan.txt')
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip().startswith('+')]
    except OSError:
        return []


def build_report_dict(target):
    hosts = get_live_hosts()
    ports_by_host = get_open_ports(os.path.join(STAGE2, 'top_1000_portscan.xml'))
    os_matches = get_os_matches()
    services = get_services()
    certs = get_ssl_certs()
    ciphers = get_ssl_ciphers()
    headers_check = get_headers_check()
    vuln_findings = get_vuln_findings()
    nikto_findings = get_nikto_findings()

    report = {
        'target': target,
        'hosts': [],
    }

    for addr, hostname in hosts.items():
        report['hosts'].append({
            'ip': addr,
            'hostname': hostname,
            'open_ports': ports_by_host.get(addr, []),
            'os_guesses': os_matches.get(addr, []),
            'services': services.get(addr, []),
            'ssl_certs': certs.get(addr, []),
            'ssl_ciphers': ciphers.get(addr, []),
            'headers_check': headers_check,
            'vuln_findings': vuln_findings,
            'nikto_findings': nikto_findings,
        })

    return report


if __name__ == '__main__':
    print(json.dumps(build_report_dict('test'), ensure_ascii=False, indent=2))