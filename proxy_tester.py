"""
Proxy Tester Library (Python port dari proxy-tester.js)
=====================================================================
Testing kualitas proxy: exit IP, geolocation, anonymity, blacklist,
Adsterra safety.

Menggunakan:
    - aiohttp untuk HTTP/HTTPS proxy (parameter `proxy=`)
    - aiohttp_socks untuk SOCKS4/SOCKS5 proxy
    - socket.getaddrinfo untuk DNSBL blacklist check
"""

import asyncio
import os
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import quote

import aiohttp
from aiohttp_socks import ProxyConnector

from proxy_parser import Proxy, format_proxy_string


# ============================================================
# Konfigurasi (bisa di-override via env var)
# ============================================================
TCP_CONNECT_TIMEOUT_MS = int(os.environ.get('PROXY_TCP_CONNECT_TIMEOUT_MS', '4000'))
HTTP_REQUEST_TIMEOUT_MS = int(os.environ.get('PROXY_HTTP_REQUEST_TIMEOUT_MS', '6000'))
OVERALL_PER_PROXY_TIMEOUT_MS = int(os.environ.get('PROXY_OVERALL_TIMEOUT_MS', '12000'))
DNS_LOOKUP_TIMEOUT_MS = int(os.environ.get('PROXY_DNS_TIMEOUT_MS', '3000'))
USER_AGENT = os.environ.get(
    'PROXY_TEST_USER_AGENT',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
)

# Target URL untuk test (default: ip-api.com karena sekali request dapat
# exit IP + geo + proxy/hosting flag, yang semuanya diperlukan untuk
# Adsterra safety assessment).
DEFAULT_TEST_URL = 'http://ip-api.com/json/?fields=query,country,countryCode,city,isp,org,as,proxy,hosting'
FALLBACK_GEO_URL = 'https://ipwho.is/'
SERVER_IP_URL = 'https://api.ipify.org?format=json'

# DNS Blacklists
BLACKLISTS = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
    'b.barracudacentral.org',
]


# ============================================================
# Result dataclass
# ============================================================
@dataclass
class TestResult:
    ok: bool = False
    latency_ms: int = 0
    exit_ip: Optional[str] = None
    exit_country: Optional[str] = None
    exit_city: Optional[str] = None
    exit_isp: Optional[str] = None
    anonymity: str = 'unknown'           # 'transparent' | 'anonymous' | 'elite' | 'unknown'
    dns_leak: Optional[bool] = None
    dns_server: Optional[str] = None
    webrtc_leak: Optional[bool] = None
    blacklisted: Optional[bool] = None
    blacklist_sources: List[str] = field(default_factory=list)
    adsterra_safe: str = 'unknown'       # 'safe' | 'risky' | 'unsafe' | 'unknown'
    quality_score: int = 0
    error: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    proxy: Optional[Proxy] = None        # referensi ke proxy yang di-test

    def to_dict(self) -> Dict[str, Any]:
        d = {
            'ok': self.ok,
            'latencyMs': self.latency_ms,
            'exitIp': self.exit_ip,
            'exitCountry': self.exit_country,
            'exitCity': self.exit_city,
            'exitIsp': self.exit_isp,
            'anonymity': self.anonymity,
            'dnsLeak': self.dns_leak,
            'dnsServer': self.dns_server,
            'webRtcLeak': self.webrtc_leak,
            'blacklisted': self.blacklisted,
            'blacklistSources': self.blacklist_sources,
            'adsterraSafe': self.adsterra_safe,
            'qualityScore': self.quality_score,
            'error': self.error,
            'proxy': self.proxy.to_dict() if self.proxy else None,
            'proxyString': format_proxy_string(self.proxy) if self.proxy else None,
        }
        return d


# ============================================================
# HTTP/HTTPS proxy fetch (via aiohttp `proxy=` parameter)
# ============================================================
async def fetch_through_http_proxy(proxy: Proxy, target_url: str, timeout_ms: int) -> Dict[str, Any]:
    """Fetch URL via HTTP/HTTPS proxy menggunakan aiohttp."""
    proxy_url = f"http://{proxy.host}:{proxy.port}"
    proxy_auth: Optional[aiohttp.BasicAuth] = None
    if proxy.username:
        proxy_auth = aiohttp.BasicAuth(proxy.username, proxy.password or '')

    timeout = aiohttp.ClientTimeout(total=timeout_ms / 1000)
    start = time.monotonic()
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(
            target_url,
            proxy=proxy_url,
            proxy_auth=proxy_auth,
            headers={
                'User-Agent': USER_AGENT,
                'Accept': 'application/json,text/plain,*/*',
            },
            allow_redirects=False,
            ssl=False,  # jangan strict verifikasi cert target (proxy mungkin intercept)
        ) as resp:
            body = await resp.text()
            return {
                'status': resp.status,
                'body': body,
                'latencyMs': int((time.monotonic() - start) * 1000),
            }


# ============================================================
# SOCKS proxy fetch (via aiohttp_socks ProxyConnector)
# ============================================================
async def fetch_through_socks_proxy(proxy: Proxy, target_url: str, timeout_ms: int) -> Dict[str, Any]:
    """Fetch URL via SOCKS4/SOCKS5 proxy menggunakan aiohttp_socks."""
    socks_url = format_proxy_string(proxy)  # socks5://[user:pass@]host:port
    connector = ProxyConnector.from_url(socks_url, rdns=True)
    timeout = aiohttp.ClientTimeout(total=timeout_ms / 1000)
    start = time.monotonic()
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async with session.get(
            target_url,
            headers={
                'User-Agent': USER_AGENT,
                'Accept': 'application/json,text/plain,*/*',
            },
            allow_redirects=False,
            ssl=False,
        ) as resp:
            body = await resp.text()
            return {
                'status': resp.status,
                'body': body,
                'latencyMs': int((time.monotonic() - start) * 1000),
            }


async def fetch_through_proxy(proxy: Proxy, target_url: str, timeout_ms: int = HTTP_REQUEST_TIMEOUT_MS) -> Dict[str, Any]:
    """Dispatcher: pilih fetcher berdasarkan protocol proxy."""
    if proxy.protocol in ('http', 'https'):
        return await fetch_through_http_proxy(proxy, target_url, timeout_ms)
    return await fetch_through_socks_proxy(proxy, target_url, timeout_ms)


# ============================================================
# Get server's own IP (cached)
# ============================================================
_cached_server_ip: Optional[str] = None


async def get_server_ip() -> Optional[str]:
    """Ambil IP publik server kita sendiri (untuk deteksi anonymity transparent)."""
    global _cached_server_ip
    if _cached_server_ip:
        return _cached_server_ip
    try:
        timeout = aiohttp.ClientTimeout(total=4)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(SERVER_IP_URL) as resp:
                data = await resp.json()
                _cached_server_ip = data.get('ip')
                return _cached_server_ip
    except Exception:
        return None


# ============================================================
# Geolocation + proxy/hosting flag via ip-api.com (fallback: ipwho.is)
# ============================================================
async def get_geo_through_proxy(proxy: Proxy, timeout_ms: int = HTTP_REQUEST_TIMEOUT_MS) -> Optional[Dict[str, Any]]:
    """
    Ambil exit IP, country, city, ISP, dan flag proxy/hosting melalui proxy.
    Pakai ip-api.com sebagai primary, ipwho.is sebagai fallback.
    """
    # Primary: ip-api.com
    try:
        r = await fetch_through_proxy(proxy, DEFAULT_TEST_URL, timeout_ms)
        if 200 <= r['status'] < 400 and r['body']:
            try:
                j = json_loads(r['body'])
                if j.get('query'):
                    return {
                        'exitIp': j.get('query', ''),
                        'country': j.get('country', ''),
                        'countryCode': j.get('countryCode', ''),
                        'city': j.get('city', ''),
                        'isp': j.get('isp', ''),
                        'org': j.get('org', ''),
                        'as': j.get('as', ''),
                        'isProxy': _bool_or_none(j.get('proxy')),
                        'isHosting': _bool_or_none(j.get('hosting')),
                    }
            except Exception:
                pass
    except Exception:
        pass

    # Fallback: ipwho.is
    try:
        r = await fetch_through_proxy(proxy, FALLBACK_GEO_URL, timeout_ms)
        if 200 <= r['status'] < 400 and r['body']:
            j = json_loads(r['body'])
            if j.get('success') is not False and j.get('ip'):
                conn = j.get('connection') or {}
                return {
                    'exitIp': j.get('ip', ''),
                    'country': j.get('country', ''),
                    'countryCode': j.get('country_code', ''),
                    'city': j.get('city', ''),
                    'isp': conn.get('isp', ''),
                    'org': conn.get('org', ''),
                    'as': f"AS{conn['asn']}" if conn.get('asn') else '',
                    'isProxy': None,
                    'isHosting': None,
                }
    except Exception:
        pass

    return None


def _bool_or_none(v: Any) -> Optional[bool]:
    if v is True:
        return True
    if v is False:
        return False
    return None


def json_loads(s: str) -> Dict[str, Any]:
    import json as _json
    return _json.loads(s)


# ============================================================
# Blacklist check via DNSBL
# ============================================================
async def check_blacklist(ip: Optional[str]) -> Dict[str, Any]:
    """Cek apakah IP terdaftar di DNSBL (Spamhaus, SpamCop, SORBS, Barracuda)."""
    if not ip:
        return {'blacklisted': False, 'sources': []}
    parts = ip.split('.')
    if len(parts) != 4:
        return {'blacklisted': False, 'sources': []}
    reversed_ip = '.'.join(reversed(parts))
    flagged: List[str] = []

    async def _check_one(bl: str) -> None:
        try:
            loop = asyncio.get_event_loop()
            # getaddrinfo dengan timeout
            fut = loop.getaddrinfo(
                f"{reversed_ip}.{bl}", None,
                family=socket.AF_INET, proto=socket.IPPROTO_UDP,
            )
            result = await asyncio.wait_for(fut, timeout=DNS_LOOKUP_TIMEOUT_MS / 1000)
            if result:
                flagged.append(bl)
        except Exception:
            pass

    await asyncio.gather(*[_check_one(bl) for bl in BLACKLISTS], return_exceptions=True)
    return {'blacklisted': len(flagged) > 0, 'sources': flagged}


# ============================================================
# Anonymity, Adsterra safety, quality score
# ============================================================
def detect_anonymity(server_ip: Optional[str], exit_ip: Optional[str], is_proxy_flag: Optional[bool]) -> str:
    """Deteksi tingkat anonymity: transparent / anonymous / elite / unknown."""
    if not exit_ip:
        return 'unknown'
    if server_ip and exit_ip == server_ip:
        return 'transparent'
    if is_proxy_flag is True:
        return 'anonymous'
    return 'elite'


def assess_adsterra_safety(
    blacklisted: Optional[bool],
    dns_leak: Optional[bool],
    anonymity: str,
    quality_score: int,
) -> str:
    """
    Assess apakah proxy aman untuk Adsterra.
    Rules (mirror dari proxy-tester.js):
        - blacklisted == True         -> 'unsafe'
        - anonymity == 'transparent'  -> 'unsafe'
        - dns_leak == True            -> 'risky'
        - anonymity == 'anonymous' && score < 70 -> 'risky'
        - score < 50                  -> 'risky'
        - anonymity == 'elite' && !blacklisted && score >= 70 -> 'safe'
        - else                        -> 'unknown'
    """
    if blacklisted is True:
        return 'unsafe'
    if anonymity == 'transparent':
        return 'unsafe'
    if dns_leak is True:
        return 'risky'
    if anonymity == 'anonymous' and quality_score < 70:
        return 'risky'
    if quality_score < 50:
        return 'risky'
    if anonymity == 'elite' and not blacklisted and quality_score >= 70:
        return 'safe'
    return 'unknown'


def calculate_quality_score(
    ok: bool,
    latency_ms: int,
    anonymity: str,
    blacklisted: Optional[bool],
    dns_leak: Optional[bool],
) -> int:
    """Hitung quality score 0-100 berdasarkan latency, anonymity, blacklist, dns_leak."""
    if not ok:
        return 0
    score = 50
    if latency_ms < 1000:
        score += 20
    elif latency_ms < 3000:
        score += 15
    elif latency_ms < 6000:
        score += 8
    elif latency_ms > 8000:
        score -= 10

    if anonymity == 'elite':
        score += 20
    elif anonymity == 'anonymous':
        score += 10
    elif anonymity == 'transparent':
        score -= 30

    if blacklisted is False:
        score += 10
    if blacklisted is True:
        score = 0

    if dns_leak is False:
        score += 5
    if dns_leak is True:
        score -= 15

    return max(0, min(100, score))


def get_server_dns_resolver() -> Optional[str]:
    """Ambil DNS resolver pertama yang dipakai server (untuk info dns_leak)."""
    try:
        return socket.getaddrinfo('', None)[0][4][0] if socket.getaddrinfo('', None) else None
    except Exception:
        return None


# ============================================================
# Main test function (with overall timeout)
# ============================================================
async def test_proxy_inner(proxy: Proxy) -> TestResult:
    """Test satu proxy end-to-end: geo + anonymity + blacklist + score + Adsterra safety."""
    start = time.monotonic()
    result = TestResult(proxy=proxy)

    try:
        server_ip = await get_server_ip()
        result.raw['serverIp'] = server_ip

        geo = await get_geo_through_proxy(proxy, HTTP_REQUEST_TIMEOUT_MS)
        if not geo or not geo.get('exitIp'):
            result.error = 'Tidak dapat terhubung ke proxy atau proxy tidak merespons (cek host:port dan kredensial)'
            result.latency_ms = int((time.monotonic() - start) * 1000)
            return result

        result.exit_ip = geo['exitIp']
        result.exit_country = geo.get('countryCode') or geo.get('country') or None
        result.exit_city = geo.get('city') or None
        result.exit_isp = geo.get('isp') or geo.get('org') or None
        result.latency_ms = int((time.monotonic() - start) * 1000)
        result.ok = True
        result.raw['geo'] = geo

        result.anonymity = detect_anonymity(server_ip, result.exit_ip, geo.get('isProxy'))
        result.dns_server = get_server_dns_resolver()
        result.dns_leak = None  # tidak dideteksi di sini (perlu test DNS terpisah)

        bl = await check_blacklist(result.exit_ip)
        result.blacklisted = bl['blacklisted']
        result.blacklist_sources = bl['sources']

        result.quality_score = calculate_quality_score(
            ok=result.ok,
            latency_ms=result.latency_ms,
            anonymity=result.anonymity,
            blacklisted=result.blacklisted,
            dns_leak=result.dns_leak,
        )
        result.adsterra_safe = assess_adsterra_safety(
            blacklisted=result.blacklisted,
            dns_leak=result.dns_leak,
            anonymity=result.anonymity,
            quality_score=result.quality_score,
        )
        result.webrtc_leak = None
        return result

    except asyncio.TimeoutError:
        result.error = f'Test timeout ({OVERALL_PER_PROXY_TIMEOUT_MS}ms)'
        result.latency_ms = int((time.monotonic() - start) * 1000)
        result.ok = False
        result.raw['timeout'] = True
        return result
    except Exception as e:
        result.error = str(e) or 'Unknown error'
        result.latency_ms = int((time.monotonic() - start) * 1000)
        result.ok = False
        return result


async def test_proxy(proxy: Proxy) -> TestResult:
    """Wrapper dengan overall timeout."""
    try:
        return await asyncio.wait_for(
            test_proxy_inner(proxy),
            timeout=OVERALL_PER_PROXY_TIMEOUT_MS / 1000,
        )
    except asyncio.TimeoutError:
        return TestResult(
            ok=False,
            latency_ms=OVERALL_PER_PROXY_TIMEOUT_MS,
            anonymity='unknown',
            adsterra_safe='unknown',
            quality_score=0,
            error=f'Test timeout ({OVERALL_PER_PROXY_TIMEOUT_MS}ms)',
            raw={'timeout': True},
            proxy=proxy,
        )
    except Exception as e:
        msg = str(e) or 'Unknown error'
        return TestResult(
            ok=False,
            latency_ms=OVERALL_PER_PROXY_TIMEOUT_MS,
            anonymity='unknown',
            adsterra_safe='unknown',
            quality_score=0,
            error=msg,
            proxy=proxy,
        )


# ============================================================
# CLI entry untuk testing satu proxy
# ============================================================
if __name__ == '__main__':
    import sys
    from proxy_parser import parse_line

    if len(sys.argv) < 2:
        print("Penggunaan: python proxy_tester.py <proxy_string>")
        print("Contoh    : python proxy_tester.py 'socks5://1.2.3.4:1080'")
        sys.exit(1)

    proxy = parse_line(sys.argv[1])
    if not proxy:
        print(f"Gagal parse: {sys.argv[1]}")
        sys.exit(1)

    print(f"Testing: {format_proxy_string(proxy)}")
    result = asyncio.run(test_proxy(proxy))
    print(f"\n--- Result ---")
    print(f"OK            : {result.ok}")
    print(f"Latency       : {result.latency_ms} ms")
    print(f"Exit IP       : {result.exit_ip}")
    print(f"Country/City  : {result.exit_country} / {result.exit_city}")
    print(f"ISP           : {result.exit_isp}")
    print(f"Anonymity     : {result.anonymity}")
    print(f"Blacklisted   : {result.blacklisted} ({', '.join(result.blacklist_sources) or '-'})")
    print(f"Quality score : {result.quality_score}/100")
    print(f"Adsterra safe : {result.adsterra_safe}")
    if result.error:
        print(f"Error         : {result.error}")
