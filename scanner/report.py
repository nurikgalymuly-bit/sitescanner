#!/usr/bin/python3
import xml.etree.ElementTree as ET
import os
from datetime import datetime

STAGE1 = os.path.expanduser('~/Документы/sitescanner/reports/Stage_1')
STAGE2 = os.path.expanduser('~/Документы/sitescanner/reports/Stage_2')
OUT_FILE = os.path.expanduser('~/Документы/sitescanner/reports/report.txt')

LINE = "=" * 70
THIN = "-" * 70


def safe_parse(path):
    if not os.path.exists(path):
        return None
    try:
        return ET.parse(path).getroot()
    except ET.ParseError:
        return None


def section(title):
    return f"\n{LINE}\n{title}\n{LINE}\n"


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
            open_ports.append((portid, proto, service))
        if open_ports:
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
                matches.append(f"{match.get('name')} ({match.get('accuracy')}%)")
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
                if service_el is None:
                    services.append((portid, '?', '', ''))
                    continue
                name = service_el.get('name', '?')
                product = service_el.get('product', '')
                version = service_el.get('version', '')
                services.append((portid, name, product, version))
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
        certs = []
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
                    certs.append({
                        'portid': portid,
                        'subject': subject or 'не определено',
                        'issuer': issuer or 'не определено',
                        'valid_after': valid_after or 'не определено',
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
                    strength = 'не определено'
                    for line in output.splitlines():
                        line = line.strip()
                        if line.startswith('TLSv') or line.startswith('SSLv'):
                            protocols.append(line.rstrip(':'))
                        elif line.startswith('least strength:'):
                            strength = line.replace('least strength:', '').strip()
                    ciphers.append((portid, protocols, strength))
        result[addr] = ciphers
    return result


def build_report():
    lines = []
    lines.append(LINE)
    lines.append("ОТЧЁТ О СКАНИРОВАНИИ".center(70))
    lines.append(f"Сформирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(70))
    lines.append(LINE)

    hosts = get_live_hosts()
    lines.append(section("1. ОБНАРУЖЕННЫЕ ХОСТЫ"))
    if not hosts:
        lines.append("Живых хостов не найдено.")
    for addr, name in hosts.items():
        label = f"{addr}" + (f" ({name})" if name else "")
        lines.append(f"  • {label}")

    ports_by_host = get_open_ports(os.path.join(STAGE2, 'top_1000_portscan.xml'))
    lines.append(section("2. ОТКРЫТЫЕ ПОРТЫ (top 1000)"))
    if not ports_by_host:
        lines.append("Открытых портов не найдено.")
    for addr, ports in ports_by_host.items():
        lines.append(f"\n  Хост: {addr}")
        lines.append(f"  {THIN}")
        for portid, proto, service in ports:
            lines.append(f"    {portid:>6}/{proto:<4} {service}")

    os_matches = get_os_matches()
    lines.append(section("3. ОПРЕДЕЛЕНИЕ ОС"))
    if not os_matches:
        lines.append("Данные об ОС отсутствуют.")
    for addr, matches in os_matches.items():
        lines.append(f"\n  Хост: {addr}")
        if not matches:
            lines.append("    Не удалось определить ОС.")
        for m in matches:
            lines.append(f"    • {m}")

    services = get_services()
    lines.append(section("4. ВЕРСИИ СЕРВИСОВ"))
    if not services:
        lines.append("Данные о сервисах отсутствуют.")
    for addr, svc_list in services.items():
        lines.append(f"\n  Хост: {addr}")
        lines.append(f"  {THIN}")
        for portid, name, product, version in svc_list:
            extra = f" {product} {version}".rstrip()
            lines.append(f"    {portid:>6} {name:<12}{extra}")

    certs = get_ssl_certs()
    lines.append(section("5. SSL-СЕРТИФИКАТЫ"))
    if not certs:
        lines.append("SSL-сертификаты не проверялись или не найдены.")
    for addr, cert_list in certs.items():
        lines.append(f"\n  Хост: {addr}")
        lines.append(f"  {THIN}")
        grouped = {}
        for c in cert_list:
            key = (c['subject'], c['issuer'], c['valid_after'])
            grouped.setdefault(key, []).append(c['portid'])
        for (subject, issuer, valid_after), ports in grouped.items():
            ports_str = ", ".join(ports)
            lines.append(f"  Порты {ports_str}:")
            lines.append(f"    Кому выдан:   {subject}")
            lines.append(f"    Кем выдан:    {issuer}")
            lines.append(f"    Действует до: {valid_after}")
            if addr not in subject and not subject.endswith(addr):
                lines.append(f"    ⚠ Внимание: сертификат выписан не на {addr}, а на {subject}")
            lines.append("")

    ciphers = get_ssl_ciphers()
    lines.append(section("6. SSL/TLS ШИФРЫ"))
    if not ciphers:
        lines.append("Проверка шифров не выполнялась или данных нет.")
    for addr, cipher_list in ciphers.items():
        lines.append(f"\n  Хост: {addr}")
        lines.append(f"  {THIN}")
        for portid, protocols, strength in cipher_list:
            proto_str = ", ".join(protocols) if protocols else "не определено"
            lines.append(f"    Порт {portid}: поддерживаемые протоколы: {proto_str}, оценка защиты: {strength}")

    lines.append(f"\n{LINE}")
    lines.append("КОНЕЦ ОТЧЁТА".center(70))
    lines.append(LINE)

    return "\n".join(lines)


def main():
    report_text = build_report()
    with open(OUT_FILE, 'w', encoding='utf-8') as f:
        f.write(report_text)
    print(f"[+] Отчёт сохранён: {OUT_FILE}")


if __name__ == '__main__':
    main()