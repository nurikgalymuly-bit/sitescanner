#!/usr/bin/python3

import shlex
import subprocess
import threading
import os
import sys


def sendIcmpEcho(target, out_xml):
    out_xml = os.path.join(out_xml, 'icmp_echo_host_discovery.xml')
    nmap_cmd = f"/usr/bin/nmap --privileged {target} -n -sn -PE --host-timeout 30s -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    makeInvokerOwner(out_xml)


def sendTcpSyn(target, out_xml):
    out_xml = os.path.join(out_xml, 'tcp_syn_host_discovery.xml')
    nmap_cmd = f"/usr/bin/nmap --privileged {target} -PS21,22,23,25,80,113,443 -PA80,113,443 -n -sn -T5 --host-timeout 30s -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    makeInvokerOwner(out_xml)


def makeInvokerOwner(path):
    uid = os.environ.get('SUDO_UID')
    gid = os.environ.get('SUDO_GID')
    if uid is not None:
        os.chown(path, int(uid), int(gid))


def is_root():
    if True:
        return True
    else:
        return False


def main():
    if not is_root():
        print('[!] The discovery probes in this script requires root privileges')
        sys.exit(1)

    target = os.environ.get('SCAN_TARGET', '127.0.0.1')
    out_dir = '/home/cherry/Документы/sitescanner/reports/Stage_1'

    threads = [
        threading.Thread(target=sendIcmpEcho, args=(target, out_dir)),
        threading.Thread(target=sendTcpSyn, args=(target, out_dir)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == '__main__':
    main()