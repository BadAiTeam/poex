"""
Proxy Bulk Tester & Sorter
=====================================================================
Membaca file proxies.txt (1000+ proxy), mengetes semuanya secara
paralel (default 200 concurrent), lalu menyortir proxy yang works
berdasarkan kriteria "safe untuk Adsterra":

    Sort priority (descending):
        1. ok (true first)
        2. adsterra_safe: safe > unknown > risky > unsafe
        3. anonymity: elite > anonymous > transparent > unknown
        4. blacklisted: false > null > true
        5. latency_ms (ascending - faster first)
        6. quality_score (descending - higher first)

Hasil disimpan ke working_proxies.txt (siap dipakai langsung).

Penggunaan:
    python main.py
    python main.py --input proxies.txt --output working_proxies.txt
    python main.py -i proxies.txt -o out.txt --concurrency 100 --timeout 15000
"""

import argparse
import asyncio
import os
import sys
import time
from collections import Counter
from datetime import datetime
from typing import List

from proxy_parser import parse_proxy_content, format_proxy_string, Proxy
from proxy_tester import test_proxy, TestResult, OVERALL_PER_PROXY_TIMEOUT_MS


# ============================================================
# Konstanta sorting
# ============================================================
ADSTERRA_ORDER = {'safe': 0, 'unknown': 1, 'risky': 2, 'unsafe': 3}
ANON_ORDER = {'elite': 0, 'anonymous': 1, 'transparent': 2, 'unknown': 3}


def sort_key(r: TestResult):
    """Multi-key sort: ok → adsterra_safe → anonymity → not_blacklisted → latency → score."""
    if not r.ok:
        # Dead proxy: taruh di paling akhir (tidak akan masuk output file, tapi
        # berguna untuk in-memory sorting jika dibutuhkan)
        return (1, 99, 99, 99, 999999, -1)
    bl_rank = 0 if r.blacklisted is False else (1 if r.blacklisted is None else 2)
    return (
        0,                                                  # ok=true first
        ADSTERRA_ORDER.get(r.adsterra_safe, 99),            # safe > unknown > risky > unsafe
        ANON_ORDER.get(r.anonymity, 99),                    # elite > anonymous > transparent > unknown
        bl_rank,                                            # not blacklisted first
        r.latency_ms,                                       # faster first
        -r.quality_score,                                   # higher score first
    )


# ============================================================
# Progress reporter
# ============================================================
class ProgressReporter:
    """Print progress setiap N detik."""

    def __init__(self, total: int, interval: float = 3.0):
        self.total = total
        self.interval = interval
        self.done = 0
        self.working = 0
        self.dead = 0
        self.start_time = time.monotonic()
        self._stop = False

    def update(self, is_working: bool) -> None:
        self.done += 1
        if is_working:
            self.working += 1
        else:
            self.dead += 1

    async def run(self) -> None:
        while not self._stop and self.done < self.total:
            await asyncio.sleep(self.interval)
            self._print()
        self._print(final=True)

    def stop(self) -> None:
        self._stop = True

    def _print(self, final: bool = False) -> None:
        elapsed = time.monotonic() - self.start_time
        pct = (self.done / self.total * 100) if self.total else 0
        rate = (self.done / elapsed) if elapsed > 0 else 0
        eta = (self.total - self.done) / rate if rate > 0 else 0
        marker = 'DONE' if final else '... '
        sys.stderr.write(
            f"\r[{marker}] {self.done}/{self.total} ({pct:.1f}%) "
            f"| working={self.working} dead={self.dead} "
            f"| {rate:.1f} proxy/s | ETA {eta:.0f}s   "
        )
        sys.stderr.flush()
        if final:
            sys.stderr.write('\n')


# ============================================================
# Main test runner
# ============================================================
async def test_all_proxies(
    proxies: List[Proxy],
    concurrency: int,
    timeout_ms: int,
) -> List[TestResult]:
    """Test semua proxy dengan semaphore untuk batasi concurrency."""
    sem = asyncio.Semaphore(concurrency)
    progress = ProgressReporter(total=len(proxies))
    progress_task = asyncio.create_task(progress.run())

    # Override timeout via env var (proxy_tester baca dari env)
    os.environ['PROXY_OVERALL_TIMEOUT_MS'] = str(timeout_ms)
    # Re-import constant after env override (di-load saat module import, jadi
    # kita perlu set ulang di module proxy_tester)
    import proxy_tester
    proxy_tester.OVERALL_PER_PROXY_TIMEOUT_MS = timeout_ms

    async def _test_one(p: Proxy) -> TestResult:
        async with sem:
            result = await test_proxy(p)
            progress.update(result.ok)
            return result

    tasks = [asyncio.create_task(_test_one(p)) for p in proxies]
    try:
        results = await asyncio.gather(*tasks, return_exceptions=False)
    finally:
        progress.stop()
        await progress_task

    return list(results)


# ============================================================
# Output writer
# ============================================================
def write_output(
    results: List[TestResult],
    output_path: str,
    input_file: str,
    started_at: datetime,
    elapsed_seconds: float,
) -> dict:
    """Tulis working_proxies.txt dengan format annotated + grouped."""
    # Sort semua hasil (dead proxy akan di-skip dari output)
    sorted_results = sorted(results, key=sort_key)
    working_results = [r for r in sorted_results if r.ok]

    # Statistik
    stats = Counter()
    for r in results:
        if not r.ok:
            stats['dead'] += 1
        else:
            stats['working'] += 1
            stats[f"adsterra_{r.adsterra_safe}"] += 1
            stats[f"anon_{r.anonymity}"] += 1
            if r.blacklisted is True:
                stats['blacklisted'] += 1
            elif r.blacklisted is False:
                stats['not_blacklisted'] += 1

    # Header
    lines: List[str] = []
    lines.append("# ================================================================")
    lines.append(f"# Proxy Test Results - {started_at.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("# ================================================================")
    lines.append(f"# Input file        : {input_file}")
    lines.append(f"# Total tested      : {len(results)}")
    lines.append(f"# Working           : {stats['working']}")
    lines.append(f"# Failed/Dead       : {stats['dead']}")
    lines.append(f"# Adsterra-SAFE     : {stats.get('adsterra_safe', 0)}   (elite + not blacklisted + score>=70)")
    lines.append(f"# Adsterra-UNKNOWN  : {stats.get('adsterra_unknown', 0)}")
    lines.append(f"# Adsterra-RISKY    : {stats.get('adsterra_risky', 0)}")
    lines.append(f"# Adsterra-UNSAFE   : {stats.get('adsterra_unsafe', 0)}")
    lines.append(f"# Elite anon        : {stats.get('anon_elite', 0)}")
    lines.append(f"# Anonymous         : {stats.get('anon_anonymous', 0)}")
    lines.append(f"# Transparent       : {stats.get('anon_transparent', 0)}")
    lines.append(f"# Blacklisted       : {stats.get('blacklisted', 0)} / {stats.get('not_blacklisted', 0)} not")
    lines.append(f"# Elapsed time      : {elapsed_seconds:.1f}s")
    lines.append("# ================================================================")
    lines.append("# Sort key (descending priority):")
    lines.append("#   1. ok (true first)")
    lines.append("#   2. adsterra_safe: safe > unknown > risky > unsafe")
    lines.append("#   3. anonymity:    elite > anonymous > transparent > unknown")
    lines.append("#   4. blacklisted:  false > null > true")
    lines.append("#   5. latency_ms:   ascending (faster first)")
    lines.append("#   6. quality_score: descending (higher first)")
    lines.append("# ================================================================")
    lines.append("# Format: <proxy_url>  # <latency>ms | <country> | <anon> | score=<n> | <adsterra> | bl=<yes/no>")
    lines.append("# Untuk pakai: grep -v '^#' working_proxies.txt | awk '{print $1}'")
    lines.append("# ================================================================")
    lines.append("")

    # Grouped output by Adsterra safety level
    groups = [
        ('safe',    'Adsterra-SAFE    (elite + not blacklisted + score>=70) — RECOMMENDED for Adsterra'),
        ('unknown', 'Adsterra-UNKNOWN (tidak memenuhi kriteria safe tapi tidak ada red flag)'),
        ('risky',   'Adsterra-RISKY   (latency jelek / anon lemah / score < 70)'),
        ('unsafe',  'Adsterra-UNSAFE  (blacklisted atau transparent) — HINDARI untuk Adsterra'),
    ]

    for level, title in groups:
        group_results = [r for r in working_results if r.adsterra_safe == level]
        if not group_results:
            continue
        lines.append(f"# --- {title} | {len(group_results)} proxies ---")
        for r in group_results:
            proxy_str = format_proxy_string(r.proxy)
            bl_str = 'yes' if r.blacklisted is True else ('no' if r.blacklisted is False else '?')
            country = (r.exit_country or '??').upper()
            city = r.exit_city or ''
            isp = r.exit_isp or ''
            location = f"{country}/{city}" if city else country
            annotation = (
                f"# {r.latency_ms}ms | {location:<14} | {r.anonymity:<11} | "
                f"score={r.quality_score:>3} | adsterra={r.adsterra_safe:<7} | bl={bl_str} | {isp}"
            )
            # Pad proxy string biar kolom annotation aligned (max 60 char proxy)
            padded_proxy = proxy_str.ljust(min(60, max(len(proxy_str) + 2, 30)))
            lines.append(f"{padded_proxy}  {annotation}")
        lines.append("")

    # Tulis file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    return {
        'total': len(results),
        'working': stats['working'],
        'dead': stats['dead'],
        'safe': stats.get('adsterra_safe', 0),
        'unknown': stats.get('adsterra_unknown', 0),
        'risky': stats.get('adsterra_risky', 0),
        'unsafe': stats.get('adsterra_unsafe', 0),
        'elite': stats.get('anon_elite', 0),
        'anonymous': stats.get('anon_anonymous', 0),
        'transparent': stats.get('anon_transparent', 0),
        'blacklisted': stats.get('blacklisted', 0),
    }


# ============================================================
# Console summary printer
# ============================================================
def print_console_summary(
    stats: dict,
    results: List[TestResult],
    elapsed: float,
    output_path: str,
) -> None:
    """Print ringkasan ke stdout."""
    print("\n" + "=" * 60)
    print(f"  PROXY TEST SELESAI  ({elapsed:.1f}s)")
    print("=" * 60)
    print(f"  Total diuji        : {stats['total']}")
    print(f"  Working            : {stats['working']}")
    print(f"  Dead/Failed        : {stats['dead']}")
    print("-" * 60)
    print(f"  Adsterra-SAFE      : {stats['safe']:>4}   <- target utama untuk Adsterra")
    print(f"  Adsterra-UNKNOWN   : {stats['unknown']:>4}")
    print(f"  Adsterra-RISKY     : {stats['risky']:>4}")
    print(f"  Adsterra-UNSAFE    : {stats['unsafe']:>4}   <- hindari")
    print("-" * 60)
    print(f"  Anonymity elite    : {stats['elite']}")
    print(f"  Anonymity anonymous: {stats['anonymous']}")
    print(f"  Anonymity transpar : {stats['transparent']}")
    print(f"  Blacklisted (DNSBL): {stats['blacklisted']}")
    print("=" * 60)
    print(f"  Output: {output_path}")
    print("=" * 60)

    # Tampilkan top 10 proxy terbaik di console
    working = sorted([r for r in results if r.ok], key=sort_key)
    if working:
        print("\n  TOP 10 PROXY TERBAIK (Adsterra-safe first):")
        print("  " + "-" * 56)
        for i, r in enumerate(working[:10], 1):
            proxy_str = format_proxy_string(r.proxy)
            if len(proxy_str) > 50:
                proxy_str = proxy_str[:47] + '...'
            country = (r.exit_country or '??').upper()
            bl_str = 'yes' if r.blacklisted is True else 'no'
            print(f"  {i:>2}. {proxy_str:<50} | {r.latency_ms:>4}ms | {country} | {r.anonymity:<9} | s={r.quality_score:>3} | {r.adsterra_safe}")
        print("  " + "-" * 56)

    # Tampilkan beberapa error umum dari dead proxy
    dead = [r for r in results if not r.ok]
    if dead:
        error_counts = Counter()
        for r in dead:
            err = (r.error or 'Unknown')[:80]
            # Normalisasi pesan error
            if 'timeout' in err.lower():
                err = 'Timeout'
            elif 'refused' in err.lower() or 'connection refused' in err.lower():
                err = 'Connection refused'
            elif 'unreachable' in err.lower():
                err = 'Network unreachable'
            elif 'resolve' in err.lower():
                err = 'DNS resolve failed'
            elif 'auth' in err.lower() or '407' in err:
                err = 'Auth failed'
            elif 'socks' in err.lower():
                err = 'SOCKS handshake failed'
            error_counts[err] += 1

        print(f"\n  Distribusi error ({len(dead)} dead proxy):")
        for err, count in error_counts.most_common(8):
            print(f"    {count:>4}x  {err}")
        if len(error_counts) > 8:
            print(f"         ... dan {len(error_counts) - 8} jenis error lain")

    print()


# ============================================================
# Entry point
# ============================================================
async def async_main(args: argparse.Namespace) -> int:
    input_path = args.input
    output_path = args.output
    concurrency = args.concurrency
    timeout_ms = args.timeout

    # Validasi file input
    if not os.path.isfile(input_path):
        print(f"ERROR: File input tidak ditemukan: {input_path}", file=sys.stderr)
        return 1

    # Baca & parse file
    print(f"\n[1/3] Membaca file proxy: {input_path}")
    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()
    proxies, parse_errors = parse_proxy_content(content, input_path)
    print(f"      Parsed: {len(proxies)} proxy valid | {len(parse_errors)} baris gagal parse")

    if not proxies:
        print("\nERROR: Tidak ada proxy valid di file input.", file=sys.stderr)
        return 1

    if parse_errors:
        print(f"\n      Contoh 5 baris yang gagal parse:")
        for e in parse_errors[:5]:
            print(f"        Line {e['line']}: {e['raw'][:60]} -> {e['reason']}")

    # Test semua proxy
    started_at = datetime.now()
    print(f"\n[2/3] Testing {len(proxies)} proxy dengan {concurrency} concurrent (timeout {timeout_ms}ms/proxy)")
    t0 = time.monotonic()
    results = await test_all_proxies(proxies, concurrency, timeout_ms)
    elapsed = time.monotonic() - t0

    # Tulis output
    print(f"\n[3/3] Menyortir & menulis output ke: {output_path}")
    stats = write_output(results, output_path, input_path, started_at, elapsed)

    # Console summary
    print_console_summary(stats, results, elapsed, output_path)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Bulk proxy tester & sorter — optimasi untuk cari proxy Adsterra-safe.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh pemakaian:
  python main.py                                    # pakai default
  python main.py -i proxies.txt -o out.txt          # custom input/output
  python main.py -c 100 --timeout 15000             # 100 concurrent, timeout 15s
  python main.py -i myproxies.json -o working.txt   # input JSON

Env vars (opsional):
  PROXY_TCP_CONNECT_TIMEOUT_MS  (default 4000)
  PROXY_HTTP_REQUEST_TIMEOUT_MS (default 6000)
  PROXY_DNS_TIMEOUT_MS          (default 3000)
  PROXY_TEST_USER_AGENT         (default Chrome 120)
        """,
    )
    parser.add_argument('-i', '--input', default='proxies.txt',
                        help='File input berisi daftar proxy (default: proxies.txt)')
    parser.add_argument('-o', '--output', default='working_proxies.txt',
                        help='File output untuk proxy yang works (default: working_proxies.txt)')
    parser.add_argument('-c', '--concurrency', type=int, default=200,
                        help='Jumlah proxy yang di-test bersamaan (default: 200)')
    parser.add_argument('--timeout', type=int, default=OVERALL_PER_PROXY_TIMEOUT_MS,
                        help=f'Overall timeout per proxy dalam ms (default: {OVERALL_PER_PROXY_TIMEOUT_MS})')
    args = parser.parse_args()

    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\n\nDihentikan user. Bye.", file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
