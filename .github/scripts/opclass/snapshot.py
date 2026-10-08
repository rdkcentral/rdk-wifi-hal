#!/usr/bin/env python3
"""Op-class round-trip snapshot (temporary advisory CI check, from LTE-3093).

Builds the HAL's op-class selection (extract.py) together with one build leg's hostap
src/common/ieee802_11_common.c, sweeps every country/band/channel/bandwidth (driver.c),
and prints the cases whose op class does not map back to the channel's frequency
(BADFREQ) or that the HAL rejects (REJECT), grouped by country set.

CI compares the output with baseline-<HOSTAPD_VERSION>.txt. A PR that changes the
mapping on purpose regenerates the baseline in the same PR:
    snapshot.py HAL_TREE HOSTAP_DIR HALIF_INCLUDE 210 > baseline-210.txt

usage: snapshot.py HAL_TREE HOSTAP_DIR HALIF_INCLUDE HOSTAPD_VERSION
       snapshot.py --compare BASELINE CURRENT   (markdown report, per country)
"""
import hashlib
import os
import subprocess
import sys
import tempfile
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
BANDS = {'1': '2.4G', '2': '5G', '16': '6G'}                                    # wifi_freq_bands_t
BW = {'1': '20', '2': '40', '4': '80', '8': '160', '16': '80+80', '32': '320'}  # wifi_channelBandwidth_t


def sweep(tree, hostap, halif, version, work):
    subprocess.run([sys.executable, f'{HERE}/extract.py', tree, f'{work}/extracted.c'], check=True)
    subprocess.run([
        os.environ.get('CC', 'gcc'), '-std=gnu11', '-w', f'-DHOSTAPD_VERSION={version}',
        f'-I{work}', f'-I{halif}', f'-I{hostap}/src', f'-I{hostap}/src/utils',
        f'{HERE}/driver.c', f'{hostap}/src/common/ieee802_11_common.c', '-o', f'{work}/sweep',
        # hostap's file references helpers (wpabuf, os_*) the sweep never calls
        '-Wl,--unresolved-symbols=ignore-all',
    ], check=True)
    return subprocess.run([f'{work}/sweep'], check=True, capture_output=True, text=True).stdout


def countries(ccs, all_ccs):
    """Short, diff-friendly country set: 'ALL', 'ALL except CA US', or 'GR'."""
    if ccs == all_ccs:
        return 'ALL'
    if len(ccs) > len(all_ccs) // 2:
        return 'ALL except ' + ' '.join(sorted(all_ccs - ccs))
    return ' '.join(sorted(ccs))


def snapshot(tree, hostap, halif, version):
    with tempfile.TemporaryDirectory() as work:
        out = sweep(tree, hostap, halif, version, work)

    groups, all_ccs = defaultdict(set), set()
    for line in out.splitlines():
        status, cc, band, ch, bw, *rest = line.split()
        all_ccs.add(cc)
        if status == 'OK':
            continue
        detail = f' op{rest[0]} -> {rest[1]} (want {rest[2]})' if status == 'BADFREQ' else ''
        groups[(int(band), int(ch), int(bw), status, detail)].add(cc)

    common = f'{hostap}/src/common/ieee802_11_common.c'
    digest = hashlib.sha256(open(common, 'rb').read()).hexdigest()[:16]
    print(f'# {os.path.basename(os.path.normpath(hostap))} ieee802_11_common.c sha256:{digest}')
    print(f'# countries: {" ".join(sorted(all_ccs))}')
    for (band, ch, bw, status, detail), ccs in sorted(groups.items()):
        print(f'{status} {BANDS[str(band)]} ch{ch} bw{BW[str(bw)]}{detail}: {countries(ccs, all_ccs)}')


def per_country(path):
    """Snapshot file -> ({(status, band, ch, bw, cc): detail}, hostap header line)."""
    lines = open(path).read().splitlines()
    all_ccs = set(next(l for l in lines if l.startswith('# countries:')).split()[2:])
    pairs = {}
    for line in lines:
        if line.startswith('#'):
            continue
        head, _, who = line.rpartition(': ')
        status, band, ch, bw = head.split()[:4]
        detail = head[len(f'{status} {band} {ch} {bw}'):]
        if who == 'ALL':
            ccs = all_ccs
        elif who.startswith('ALL except '):
            ccs = all_ccs - set(who.split()[2:])
        else:
            ccs = set(who.split())
        for cc in ccs:
            pairs[(status, band, ch, bw, cc)] = detail
    return pairs, lines[0], all_ccs


def compare(baseline, current):
    base, base_hdr, _ = per_country(baseline)
    cur, cur_hdr, all_ccs = per_country(current)
    order = {b: i for i, b in enumerate(BANDS.values())}

    def render(keys, details):
        groups = defaultdict(set)
        for status, band, ch, bw, cc in keys:
            groups[(status, band, ch, bw, details[(status, band, ch, bw, cc)])].add(cc)
        def sort_key(k):
            return (order[k[1]], int(k[2][2:]), int(k[3][2:].split('+')[0]), k[0])
        return [f'{s} {b} {c} {w}{d}: {countries(ccs, all_ccs)}'
                for (s, b, c, w, d), ccs in sorted(groups.items(), key=lambda g: sort_key(g[0]))]

    new = cur.keys() - base.keys()
    gone = base.keys() - cur.keys()
    changed = {k for k in cur.keys() & base.keys() if cur[k] != base[k]}
    if base_hdr != cur_hdr:
        print("⚠️ hostap's ieee802_11_common.c differs from the baseline's: some differences "
              "may come from hostap, not this PR.\n")
    for title, keys, details, open_ in (
            ('❌ newly broken', new, cur, True),
            ('🔁 still broken, different op class', changed, cur, True),
            ('✅ no longer broken', gone, base, False)):
        if keys:
            lines = render(keys, details)
            print(f'<details{" open" if open_ else ""}><summary>{title}: {len(lines)}</summary>\n')
            print('```')
            print('\n'.join(lines))
            print('```\n</details>\n')
    if not (new or gone or changed):
        print('no per-country change (only the header or grouping differs)')


def main():
    if sys.argv[1] == '--compare':
        compare(sys.argv[2], sys.argv[3])
    else:
        snapshot(*sys.argv[1:5])


if __name__ == '__main__':
    main()
