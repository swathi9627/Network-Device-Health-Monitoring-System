"""Minimal SNMP v2c GET client (pure Python, no extra packages)."""
import os
import socket


def _len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(t, v):
    return bytes([t]) + _len(len(v)) + v


def _int(n):
    size = max(1, (n.bit_length() + 8) // 8)
    return _tlv(0x02, n.to_bytes(size, "big", signed=True))


def _oid(s):
    p = [int(x) for x in s.strip(".").split(".")]
    out = bytearray([40 * p[0] + p[1]])
    for x in p[2:]:
        chunk = [x & 0x7F]
        x >>= 7
        while x:
            chunk.append(0x80 | (x & 0x7F))
            x >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, bytes(out))


def _read(b, i):
    t, l = b[i], b[i + 1]
    i += 2
    if l & 0x80:
        k = l & 0x7F
        l = int.from_bytes(b[i:i + k], "big")
        i += k
    return t, b[i:i + l], i + l


def _decode_oid(v):
    p, x = [v[0] // 40, v[0] % 40], 0
    for c in v[1:]:
        x = (x << 7) | (c & 0x7F)
        if not c & 0x80:
            p.append(x)
            x = 0
    return ".".join(map(str, p))


def _decode_value(t, v):
    if t == 0x02:
        return int.from_bytes(v, "big", signed=True)
    if t in (0x41, 0x42, 0x43, 0x46):          # counter, gauge, timeticks
        return int.from_bytes(v, "big")
    if t == 0x04:
        return v.decode("utf-8", "replace")
    if t == 0x06:
        return _decode_oid(v)
    return None                                # null / noSuchObject / etc.


def parse_pdu(data):
    """Return (pdu_type, request_id, [(oid, value), ...])."""
    _, msg, _ = _read(data, 0)
    _, _, i = _read(msg, 0)                    # version
    _, _, i = _read(msg, i)                    # community
    pdu_t, pdu, _ = _read(msg, i)
    _, rid, j = _read(pdu, 0)
    _, _, j = _read(pdu, j)                    # error-status
    _, _, j = _read(pdu, j)                    # error-index
    _, vbs, _ = _read(pdu, j)
    out, k = [], 0
    while k < len(vbs):
        _, vb, k = _read(vbs, k)
        t1, o, m = _read(vb, 0)
        t2, v, _ = _read(vb, m)
        out.append((_decode_oid(o), _decode_value(t2, v)))
    return pdu_t, int.from_bytes(rid, "big", signed=True), out


def get(host, oids, community="public", port=161, timeout=2.0):
    """SNMP v2c GET. Returns {oid: value}. Raises OSError on timeout."""
    rid = int.from_bytes(os.urandom(3), "big") + 1
    vbs = b"".join(_tlv(0x30, _oid(o) + _tlv(0x05, b"")) for o in oids)
    pdu = _tlv(0xA0, _int(rid) + _int(0) + _int(0) + _tlv(0x30, vbs))
    msg = _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + pdu)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (host, port))
        data, _ = s.recvfrom(65535)
    finally:
        s.close()
    _, _, items = parse_pdu(data)
    return dict(items)