#!/usr/bin/env python3
import re, subprocess, sys

result = subprocess.run(
    ["cargo", "test"] + sys.argv[1:],
    capture_output=True,
    text=True
)

data = result.stdout + result.stderr
sys.stdout.write(data)


file_re   = re.compile(r'Running tests/([\w/]+)\.rs\s')
unit_re   = re.compile(r'Running unittests')
doc_re    = re.compile(r'Doc-tests (\S+)')
binary_re = re.compile(r'/deps/([\w-]+)-[0-9a-f]{10,}')
result_re = re.compile(r'(\d+) passed; (\d+) failed;.*?finished in ([\d.]+)s')

groups, cur = [], None

for line in data.splitlines():
    if m := file_re.search(line):
        cur = m.group(1)
    elif unit_re.search(line):
        if bm := binary_re.search(line):
            cur = bm.group(1)
    elif m := doc_re.search(line):
        cur = f"doc/{m.group(1)}"
    elif m := result_re.search(line):
        p, f, t = int(m.group(1)), int(m.group(2)), float(m.group(3))
        if p + f > 0:
            groups.append((cur or '?', p, f, t))
        cur = None

if not groups:
    sys.exit(0)

tp = sum(g[1] for g in groups)
tf = sum(g[2] for g in groups)
tn = tp + tf
tt = sum(g[3] for g in groups)
pp = round(100 * tp / tn) if tn else 0
w  = max(len(g[0]) for g in groups)
sep = '─' * (w + 32)

print(f"\n{sep}")
print(f"{tn} tests  [{tt:.1f}s]")
print(f"{pp}% passed  {100 - pp}% failed\n")
print("tests for\n")
for name, p, f, t in groups:
    n   = p + f
    pct = round(100 * p / n) if n else 0
    sym = "✓" if f == 0 else "✗"
    print(f"  {sym} {name:<{w}}  {pct:3}% passed  [{t:.1f}s]")
print(sep)