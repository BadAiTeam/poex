"""
Proxy Parser Library (Python port dari proxy-parser.js v2.0)
=====================================================================
Mendukung berbagai format umum proxy dari file .txt dan .json.

Format teks (.txt) yang didukung (satu baris = satu proxy):
    1. host:port                                    -> http (default)
    2. protocol://host:port                         -> protocol
    3. protocol://user:pass@host:port               -> protocol + auth
    4. user:pass@host:port                          -> http + auth
    5. host:port:user:pass                          -> http + auth
    6. host:port:user:pass:protocol                 -> protocol + auth
    7. host:port:protocol                           -> protocol
    8. host:port:protocol:user:pass                 -> protocol + auth
    9. host:port:country:protocol                   -> protocol + country
   10. host:port:country:user:pass:protocol         -> full

Format separator alternatif:
    - space:    "socks5 1.2.3.4 1080"
    - tab:      "socks5\\t1.2.3.4\\t1080"
    - comma:    "socks5,1.2.3.4,1080"  (CSV)
    - pipe:     "socks5|1.2.3.4|1080"
    - semicolon:"socks5;1.2.3.4;1080"

Format JSON yang didukung:
    A. Array string:        ["host:port", "http://1.2.3.4:8080"]
    B. Array object:        [{"host":"1.2.3.4", "port":8080, "protocol":"http"}]
    C. Object with proxies: {"proxies": [...]}
    D. Mixed / partial:     {"ip":"1.2.3.4", "port":8080, "type":"socks5"}

Field aliases JSON:
    - protocol | type | scheme | proto | proxy_type | kind | ptype | proxyType
    - host | ip | address | server | hostname | ip_address | ipAddress
    - port | p | prt
    - username | user | login
    - password | pass | pwd
    - country | cc | iso | country_code
    - Numeric type codes: 1=http, 2=https, 3=socks4, 4=socks4, 5=socks5, 6=socks5
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple


# ============================================================
# Konstanta
# ============================================================
VALID_PROTOCOLS = ['http', 'https', 'socks4', 'socks5']

PROTOCOL_ALIASES = {
    'socks': 'socks5',
    'socks5h': 'socks5',
    'socks4a': 'socks4',
    'http_proxy': 'http',
    'https_proxy': 'https',
    'ssl': 'https',
    'tls': 'https',
    'h': 'http',
    's': 'https',
}

NUMERIC_TYPE_MAP = {
    1: 'http',
    2: 'https',
    3: 'socks4',
    4: 'socks4',
    5: 'socks5',
    6: 'socks5',
}


# ============================================================
# Dataclass proxy
# ============================================================
@dataclass
class Proxy:
    protocol: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    country: Optional[str] = None
    source: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'protocol': self.protocol,
            'host': self.host,
            'port': self.port,
            'username': self.username,
            'password': self.password,
            'country': self.country,
            'source': self.source,
            'note': self.note,
        }


# ============================================================
# Helper functions
# ============================================================
def normalize_protocol(proto: Optional[str]) -> str:
    """Normalisasi string protocol ke salah satu dari VALID_PROTOCOLS."""
    if not proto:
        return 'http'
    p = str(proto).strip().lower().rstrip(':')
    p = re.sub(r'_?proxy$', '', p)
    if p in VALID_PROTOCOLS:
        return p
    if p in PROTOCOL_ALIASES:
        return PROTOCOL_ALIASES[p]
    for valid in VALID_PROTOCOLS:
        if valid in p:
            return valid
    return 'http'


def is_protocol_keyword(s: Optional[str]) -> bool:
    """Deteksi apakah string adalah keyword protocol yang valid."""
    if not s:
        return False
    p = str(s).strip().lower().rstrip(':')
    p = re.sub(r'_?proxy$', '', p)
    if p in VALID_PROTOCOLS:
        return True
    if p in PROTOCOL_ALIASES:
        return True
    return False


def is_valid_port(port: Any) -> bool:
    """Cek apakah nilai port valid (integer 1-65535)."""
    try:
        n = int(port)
    except (TypeError, ValueError):
        return False
    return isinstance(n, int) and 1 <= n <= 65535


def is_valid_host(host: Optional[str]) -> bool:
    """Cek apakah host valid (IPv4 atau hostname)."""
    if not host:
        return False
    h = host.strip()
    if not h or len(h) > 253:
        return False
    if h.startswith('[') and h.endswith(']'):
        return len(h) > 2
    ipv4_re = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    if ipv4_re.match(h):
        return all(int(octet) <= 255 for octet in h.split('.'))
    hostname_re = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$'
    )
    return bool(hostname_re.match(h))


def is_country_code(s: Optional[str]) -> bool:
    """Cek apakah string mirip country code (2-3 huruf uppercase)."""
    if not s:
        return False
    return bool(re.match(r'^[A-Z]{2,3}$', str(s).strip()))


# ============================================================
# Parser utama: parse satu baris
# ============================================================
# Strategy 1: URL-like format  protocol://[user:pass@]host:port
_URL_LIKE_RE = re.compile(
    r'^(?:(\w+)://)?'                                     # protocol://
    r'(?:([^\s:@/]+):([^\s:@/]+)@)?'                      # user:pass@
    r'([^:/@\s]+|\[[0-9a-fA-F:]+\]):'                     # host
    r'(\d{1,5})'                                          # port
    r'(?:/.*)?$',                                         # path opsional
    re.IGNORECASE,
)

# Strategy 2 & 3: separator alternatif
_ALT_SEP_RE = re.compile(r'[\s,|;\t]+')


def parse_line(raw_line: str, default_source: Optional[str] = None) -> Optional[Proxy]:
    """Parse satu baris teks menjadi Proxy object (atau None jika gagal)."""
    if not raw_line:
        return None
    line = raw_line.strip()
    if not line or line.startswith('#') or line.startswith('//'):
        return None

    # Buang tanda kutip luar
    cleaned = re.sub(r'^["\']|["\']$', '', line).strip()
    if not cleaned:
        return None

    # Buang trailing inline comment (mis. "socks5://1.2.3.4:1080 #fast")
    # Hanya jika ada whitespace sebelum #, untuk hindari konflik dengan password
    cleaned = re.sub(r'\s+#.*$', '', cleaned).strip()
    if not cleaned:
        return None

    # === Strategy 1: URL-like format ===
    m = _URL_LIKE_RE.match(cleaned)
    if m:
        host = m.group(4)
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        try:
            port = int(m.group(5))
        except ValueError:
            port = 0
        protocol = normalize_protocol(m.group(1)) if m.group(1) else 'http'
        if not is_valid_host(host) or not is_valid_port(port):
            return None
        return Proxy(
            protocol=protocol,
            host=host,
            port=port,
            username=m.group(2) or None,
            password=m.group(3) or None,
            country=None,
            source=default_source,
            note=None,
        )

    # === Strategy 2: smart colon-separated parsing ===
    colon_parts = [p.strip() for p in cleaned.split(':') if p.strip()]
    if len(colon_parts) >= 2 and is_valid_host(colon_parts[0]):
        try:
            port_candidate = int(colon_parts[1])
        except ValueError:
            port_candidate = 0
        if is_valid_port(port_candidate):
            host = colon_parts[0]
            port = port_candidate
            rest = colon_parts[2:]

            # Scan rest untuk keyword protocol di posisi manapun
            protocol = 'http'
            protocol_idx = -1
            for i, r in enumerate(rest):
                if is_protocol_keyword(r):
                    protocol = normalize_protocol(r)
                    protocol_idx = i
                    break

            # Buang elemen protocol dari rest
            remaining = list(rest)
            if protocol_idx >= 0:
                remaining.pop(protocol_idx)

            username = None
            password = None
            country = None

            if not remaining:
                pass  # host:port atau host:port:protocol
            elif len(remaining) == 1:
                if is_country_code(remaining[0]):
                    country = remaining[0]
                else:
                    username = remaining[0]
            elif len(remaining) == 2:
                # user:pass atau country:user panjang (jarang)
                if is_country_code(remaining[0]) and len(remaining[1]) > 30:
                    country = remaining[0]
                    username = remaining[1]
                else:
                    username = remaining[0]
                    password = remaining[1]
            elif len(remaining) == 3:
                if is_country_code(remaining[0]):
                    country = remaining[0]
                    username = remaining[1]
                    password = remaining[2]
                elif is_country_code(remaining[2]):
                    username = remaining[0]
                    password = remaining[1]
                    country = remaining[2]
                else:
                    username = remaining[0]
                    password = remaining[1]
            else:
                # >3 sisa: ambil 2 pertama sebagai user:pass, cari country code
                for i, r in enumerate(remaining):
                    if is_country_code(r):
                        country = r
                        remaining.pop(i)
                        break
                if len(remaining) >= 1:
                    username = remaining[0]
                if len(remaining) >= 2:
                    password = remaining[1]

            return Proxy(
                protocol=protocol, host=host, port=port,
                username=username, password=password, country=country,
                source=default_source, note=None,
            )

    # === Strategy 3: separator alternatif (space, comma, pipe, semicolon, tab) ===
    sep_parts = [s.strip() for s in _ALT_SEP_RE.split(cleaned) if s.strip()]
    if len(sep_parts) >= 2:
        protocol = None
        protocol_idx = -1
        for i, s in enumerate(sep_parts):
            if is_protocol_keyword(s):
                protocol = normalize_protocol(s)
                protocol_idx = i
                break

        port = None
        port_idx = -1
        for i, s in enumerate(sep_parts):
            if i == protocol_idx:
                continue
            if re.match(r'^\d{1,5}$', s):
                n = int(s)
                if 1 <= n <= 65535:
                    port = n
                    port_idx = i
                    break

        host = None
        host_idx = -1
        for i, s in enumerate(sep_parts):
            if i == protocol_idx or i == port_idx:
                continue
            if re.match(r'^\d+$', s):
                continue  # skip angka murni (port alternatif)
            if is_valid_host(s):
                host = s
                host_idx = i
                break

        if host and port:
            remaining = [
                s for i, s in enumerate(sep_parts)
                if i != protocol_idx and i != port_idx and i != host_idx
            ]
            username = None
            password = None
            country = None

            if len(remaining) == 1:
                if is_country_code(remaining[0]):
                    country = remaining[0]
                else:
                    username = remaining[0]
            elif len(remaining) >= 2:
                for i, r in enumerate(remaining):
                    if is_country_code(r):
                        country = r
                        remaining.pop(i)
                        break
                if len(remaining) >= 1:
                    username = remaining[0]
                if len(remaining) >= 2:
                    password = remaining[1]

            return Proxy(
                protocol=protocol or 'http',
                host=host, port=port,
                username=username, password=password, country=country,
                source=default_source, note=None,
            )

    return None


# ============================================================
# Parser untuk text content
# ============================================================
def parse_text_content(content: str, source: Optional[str] = None) -> Tuple[List[Proxy], List[Dict]]:
    """Parse konten teks multi-baris. Return (proxies, errors)."""
    proxies: List[Proxy] = []
    errors: List[Dict] = []
    lines = content.splitlines()
    for line_num, raw_line in enumerate(lines, start=1):
        trimmed = raw_line.strip()
        if not trimmed or trimmed.startswith('#') or trimmed.startswith('//'):
            continue
        parsed = parse_line(trimmed, source)
        if parsed:
            proxies.append(parsed)
            continue
        # Fallback: coba split by comma dan parse masing-masing
        sub_items = [s.strip() for s in trimmed.split(',') if s.strip()]
        if len(sub_items) > 1:
            any_parsed = False
            for sub in sub_items:
                sp = parse_line(sub, source)
                if sp:
                    proxies.append(sp)
                    any_parsed = True
            if any_parsed:
                continue
        errors.append({'line': line_num, 'raw': trimmed, 'reason': 'Format tidak dikenali'})
    return proxies, errors


# ============================================================
# Parser untuk JSON content
# ============================================================
def parse_json_content(content: str, source: Optional[str] = None) -> Tuple[List[Proxy], List[Dict]]:
    """Parse konten JSON. Mendukung array string, array object, atau object dengan field proxies/list/data/items."""
    proxies: List[Proxy] = []
    errors: List[Dict] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        errors.append({'line': 0, 'raw': content[:100], 'reason': f'JSON parse error: {e.msg}'})
        return proxies, errors

    if isinstance(data, dict) and not isinstance(data, list):
        if isinstance(data.get('proxies'), list):
            data = data['proxies']
        elif isinstance(data.get('list'), list):
            data = data['list']
        elif isinstance(data.get('data'), list):
            data = data['data']
        elif isinstance(data.get('items'), list):
            data = data['items']
        else:
            data = [data]

    if not isinstance(data, list):
        errors.append({
            'line': 0, 'raw': '',
            'reason': 'Root JSON harus berupa array atau objek dengan field proxies/list/data/items',
        })
        return proxies, errors

    for idx, item in enumerate(data, start=1):
        if isinstance(item, str):
            p = parse_line(item, source)
            if p:
                proxies.append(p)
            else:
                errors.append({'line': idx, 'raw': str(item), 'reason': 'Format string tidak valid'})
            continue
        if isinstance(item, dict):
            obj = item
            # Field aliases untuk host
            host = str(
                obj.get('host') or obj.get('ip') or obj.get('address') or
                obj.get('server') or obj.get('hostname') or
                obj.get('ip_address') or obj.get('ipAddress') or obj.get('addr') or ''
            ).strip()

            # Field aliases untuk port
            port_raw = obj.get('port') or obj.get('p') or obj.get('prt') or \
                obj.get('port_number') or obj.get('portNumber')
            try:
                port = int(port_raw) if port_raw is not None else 0
            except (TypeError, ValueError):
                port = 0

            if host and is_valid_port(port):
                # Field aliases untuk protocol
                proto_val = (obj.get('protocol') or obj.get('type') or obj.get('scheme') or
                             obj.get('proto') or obj.get('proxy_type') or obj.get('proxyType') or
                             obj.get('kind') or obj.get('ptype') or obj.get('p_type') or
                             obj.get('network'))

                if isinstance(proto_val, int) and proto_val in NUMERIC_TYPE_MAP:
                    proto_val = NUMERIC_TYPE_MAP[proto_val]
                elif isinstance(proto_val, str):
                    num_match = re.match(r'^(\d+)$', proto_val.strip())
                    if num_match:
                        n = int(num_match.group(1))
                        if n in NUMERIC_TYPE_MAP:
                            proto_val = NUMERIC_TYPE_MAP[n]

                protocol = normalize_protocol(proto_val or 'http')

                username = obj.get('username') or obj.get('user') or obj.get('login') or \
                    obj.get('u') or obj.get('usr')
                password = obj.get('password') or obj.get('pass') or obj.get('pwd') or obj.get('pw')
                country = obj.get('country') or obj.get('cc') or obj.get('iso') or \
                    obj.get('country_code') or obj.get('countryCode') or obj.get('region')
                note = obj.get('note') or obj.get('notes') or obj.get('label') or \
                    obj.get('name') or obj.get('desc') or obj.get('description')

                if is_valid_host(host):
                    proxies.append(Proxy(
                        protocol=protocol,
                        host=host,
                        port=port,
                        username=str(username) if username else None,
                        password=str(password) if password else None,
                        country=str(country).upper() if country else None,
                        source=source,
                        note=str(note) if note else None,
                    ))
                    continue

            errors.append({
                'line': idx,
                'raw': json.dumps(item)[:200],
                'reason': 'Objek tidak memiliki host/port valid',
            })
            continue
        errors.append({'line': idx, 'raw': str(item), 'reason': 'Tipe tidak didukung'})

    return proxies, errors


# ============================================================
# Parser dispatcher
# ============================================================
def parse_proxy_content(content: str, file_name: Optional[str] = None) -> Tuple[List[Proxy], List[Dict]]:
    """
    Deteksi format (txt vs json) dari ekstensi file atau dari konten,
    lalu parse dengan parser yang sesuai.
    """
    name_lower = file_name.lower() if file_name else ''
    ext = 'json' if name_lower.endswith('.json') else ('txt' if name_lower.endswith('.txt') else None)
    source = file_name or 'manual'
    trimmed = content.strip()
    if ext == 'json' or (ext is None and (trimmed.startswith('[') or trimmed.startswith('{'))):
        return parse_json_content(content, source)
    return parse_text_content(content, source)


def format_proxy_string(p: Proxy) -> str:
    """Format Proxy object ke string 'protocol://[user:pass@]host:port'."""
    s = f"{p.protocol}://"
    if p.username:
        s += p.username
        if p.password:
            s += f":{p.password}"
        s += '@'
    if ':' in p.host and not p.host.startswith('['):
        s += f"[{p.host}]:{p.port}"
    else:
        s += f"{p.host}:{p.port}"
    return s


# ============================================================
# CLI entry untuk testing mandiri
# ============================================================
if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Penggunaan: python proxy_parser.py <file_proxy>")
        sys.exit(1)
    file_path = sys.argv[1]
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    proxies, errors = parse_proxy_content(content, file_path)
    print(f"Parsed: {len(proxies)} proxy | Errors: {len(errors)}")
    print("\nContoh 10 proxy pertama:")
    for p in proxies[:10]:
        print(f"  {format_proxy_string(p)}  (country={p.country})")
    if errors:
        print(f"\nContoh 5 error pertama:")
        for e in errors[:5]:
            print(f"  Line {e['line']}: {e['raw'][:60]} -> {e['reason']}")
