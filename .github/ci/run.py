"""Run one verified real-binary fixture in an isolated Ghidra process."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--sample', required=True)
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
sample = json.loads(Path(__file__).with_name('corpus.json').read_text())['samples'][args.sample]
results = args.root / 'results'
results.mkdir(parents=True, exist_ok=True)
command = [sys.executable, '-u', str(repo / 'tests/ghidra_application.py'),
           str(args.root / sample['name']), '--ghidra', str(args.root / 'ghidra_12.2_PUBLIC'),
           '--output', str(results / 'application.json'), '--minimum-labels', str(sample['minimum_labels'])]
for address in sample.get('required_entries', []):
    command.extend(['--required-entry', address])
if sample['legacy']:
    command.append('--legacy')
for analyzer in sample['disabled_analyzers']:
    command.extend(['--disable-analyzer', analyzer])
with (results / 'run.log').open('w') as log:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in process.stdout:
        log.write(line)
        log.flush()
        print(line, end='', flush=True)
    code = process.wait()
sys.exit(code)
