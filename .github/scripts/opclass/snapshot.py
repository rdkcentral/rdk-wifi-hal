#!/usr/bin/env python3
#
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2026 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
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
    all_ccs = set(next(line for line in lines if line.startswith('# countries:')).split()[2:])
    pairs = {}
    for line in lines:
        if line.startswith('#'):
            continue
        head, _sep, who = line.rpartition(': ')
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
    base, base_hdr, _base_ccs = per_country(baseline)
    cur, cur_hdr, all_ccs = per_country(current)
    band_rank = {band_name: rank for rank, band_name in enumerate(BANDS.values())}

    def sort_key(group_key):
        status, band, ch, bw = group_key[:4]
        return (band_rank[band], int(ch[2:]), int(bw[2:].split('+')[0]), status)

    def render(keys, details):
        groups = defaultdict(set)
        for status, band, ch, bw, cc in keys:
            groups[(status, band, ch, bw, details[(status, band, ch, bw, cc)])].add(cc)
        return [f'{status} {band} {ch} {bw}{detail}: {countries(ccs, all_ccs)}'
                for (status, band, ch, bw, detail), ccs
                in sorted(groups.items(), key=lambda item: sort_key(item[0]))]

    changed = {key for key in cur.keys() & base.keys() if cur[key] != base[key]}
    sections = [  # (title, count label, lines, expanded)
        ('❌ newly broken', 'newly broken', render(cur.keys() - base.keys(), cur), True),
        ('🔁 still broken, different op class', 'op class changed', render(changed, cur), True),
        ('✅ no longer broken', 'fixed', render(base.keys() - cur.keys(), base), False),
    ]
    counts = ', '.join(f'{len(lines)} {label}' for _title, label, lines, _open in sections if lines)

    # Sum-up first: the only line most readers look at.
    print('> [!CAUTION]')
    print(f'> **Op-class round trip differs from `{baseline}`'
          f'{": " + counts if counts else " (header only)"}.**  ')
    print(f'> **If the change was deliberate, update `{baseline}` with the full snapshot below.**\n')
    if base_hdr != cur_hdr:
        print("⚠️ hostap's ieee802_11_common.c differs from the baseline's: some differences "
              "may come from hostap, not this PR.\n")
    for title, _label, lines, expanded in sections:
        if lines:
            print(f'<details{" open" if expanded else ""}><summary>{title}: {len(lines)}</summary>\n')
            print('```')
            print('\n'.join(lines))
            print('```\n</details>\n')


def main():
    if sys.argv[1] == '--compare':
        compare(sys.argv[2], sys.argv[3])
    else:
        snapshot(*sys.argv[1:5])


if __name__ == '__main__':
    main()
