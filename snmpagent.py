"""Tiny SNMP agent: answers real CPU/memory of THIS computer over SNMP.
Run:  python snmp_agent.py            (port 1161, no admin rights needed)
      python snmp_agent.py --port 1162
"""
import argparse
import platform
import socket
import time

import psutil

import snmplite as S

START = time.time()
psutil.cpu_percent(interval=None)  # prime the counter
OID_DESCR = "1.3.6.1.2.1.1.1.0"
OID_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_CPU = "1.3.6.1.2.1.25.3.3.1.2.1"      # hrProcessorLoad.1
OID_MEM_TOTAL = "1.3.6.1.4.1.2021.4.5.0"  # memTotalReal (KB)
OID_MEM_AVAIL = "1.3.6.1.4.1.2021.4.6.0"  # memAvailReal (KB)


def value_for(oid):
    if oid == OID_DESCR:
        return S._tlv(0x04, f"{platform.node()} ({platform.system()}) SNMP agent".encode())
    if oid == OID_UPTIME:
        return S._tlv(0x43, int((time.time() - START) * 100).to_bytes(5, "big").lstrip(b"\0") or b"\0")
    if oid == OID_CPU:
        return S._int(int(psutil.cpu_percent(interval=None)))
    vm = psutil.virtual_memory()
    if oid == OID_MEM_TOTAL:
        return S._int(vm.total // 1024)
    if oid == OID_MEM_AVAIL:
        return S._int(vm.available // 1024)
    return S._tlv(0x80, b"")               # noSuchObject


def respond(data, community):
    _, msg, _ = S._read(data, 0)
    _, ver, i = S._read(msg, 0)
    _, com, _ = S._read(msg, i)
    if com.decode(errors="replace") != community:
        return None
    _, rid, items = S.parse_pdu(data)
    vbs = b"".join(S._tlv(0x30, S._oid(o) + value_for(o)) for o, _ in items)
    pdu = S._tlv(0xA2, S._int(rid) + S._int(0) + S._int(0) + S._tlv(0x30, vbs))
    return S._tlv(0x30, S._tlv(0x02, ver) + S._tlv(0x04, com) + pdu)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=1161)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--community", default="public")
    a = ap.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((a.bind, a.port))
    print(f"SNMP agent on {a.bind}:{a.port}  community='{a.community}'  (Ctrl+C to stop)")
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            out = respond(data, a.community)
            if out:
                sock.sendto(out, addr)
        except KeyboardInterrupt:
            break
        except Exception:
            continue


if __name__ == "__main__":
    main()