# Converts iptoasn.com ip2asn-v4.tsv(.gz) into NetWolf's compact embedded ASN database.
# Format (little-endian):
#   char[8] "NWASN1\0\0" | u32 rangeCount | u32 asCount | u32 namesBytes | u32 sourceRows
#   rangeCount x { u32 startIp, u32 asIndex }   (asIndex 0xFFFFFFFF = not routed; a range ends where the next starts)
#   asCount    x { u32 asn, u32 nameOffset, u16 nameLength, char country[2] }
#   names (UTF-8, no terminators)
import gzip, struct, sys, ipaddress
src, dst = sys.argv[1], sys.argv[2]
opener = gzip.open if src.endswith('.gz') else open
NOT = 0xFFFFFFFF
as_index, as_list, ranges = {}, [], []
rows = 0
def clean(desc):
    # "FACEBOOK - Facebook, Inc."            -> "Facebook, Inc."
    # "AKAMAI-ASN1 Akamai International B.V." -> "Akamai International B.V."
    # "Telegram Telegram Messenger Inc"      -> "Telegram Messenger Inc"
    desc = desc.strip()
    if ' - ' in desc:
        desc = desc.split(' - ', 1)[1].strip()
    else:
        parts = desc.split(' ', 1)
        if len(parts) == 2 and parts[1].strip():
            handle, rest = parts[0], parts[1].strip()
            looks_like_handle = ('-' in handle or handle.isupper() or any(c.isdigit() for c in handle)
                                 or rest.lower().startswith(handle.lower()))
            if looks_like_handle:
                desc = rest
    return desc[:120]
with opener(src, 'rt', encoding='utf-8', errors='replace') as f:
    for line in f:
        p = line.rstrip('\n').split('\t')
        if len(p) < 5: continue
        rows += 1
        s = int(ipaddress.IPv4Address(p[0])); e = int(ipaddress.IPv4Address(p[1])); asn = int(p[2])
        if asn == 0:
            idx = NOT
        else:
            key = (asn, p[3], p[4])
            idx = as_index.get(key)
            if idx is None:
                idx = len(as_list); as_index[key] = idx
                as_list.append((asn, (p[3] if p[3] != 'None' else '--')[:2].ljust(2), clean(p[4]) or ('AS%d' % asn)))
        ranges.append((s, e, idx))
ranges.sort()
out = []
cursor = 0
for s, e, idx in ranges:
    if s > cursor: out.append((cursor, NOT))           # gap -> not routed
    if s < cursor: s = cursor                            # overlap safety
    if e < s: continue
    if out and out[-1][1] == idx: pass                   # merge with previous identical owner
    else: out.append((s, idx))
    cursor = e + 1
    if cursor > 0xFFFFFFFF: break
if cursor <= 0xFFFFFFFF and (not out or out[-1][1] != NOT): out.append((cursor, NOT))
names = bytearray(); table = []
for asn, cc, name in as_list:
    b = name.encode('utf-8'); table.append((asn, len(names), len(b), cc.encode('ascii', 'replace')[:2])); names += b
with open(dst, 'wb') as f:
    f.write(b'NWASN1\0\0' + struct.pack('<IIII', len(out), len(table), len(names), rows))
    f.write(b''.join(struct.pack('<II', s, i) for s, i in out))
    f.write(b''.join(struct.pack('<IIH2s', a, o, l, c) for a, o, l, c in table))
    f.write(names)
print('rows', rows, 'ranges', len(out), 'owners', len(table), 'names', len(names), 'bytes', 32 + 8*len(out) + 14*len(table) + len(names))
