#!/usr/bin/env python3
"""Prepare identical Caddy host fixtures with bounded bulk services."""
import argparse
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--clients', type=Path, required=True)
p.add_argument('--baseline', type=Path, required=True)
p.add_argument('--candidate', type=Path, required=True)
a = p.parse_args()
clients = a.clients.resolve()
for server in [a.baseline.resolve(), a.candidate.resolve()]:
    subprocess.run(['python3', str(clients/'scripts/prepare-native-interop.py'), '--caddy', str(server)], check=True)
bridge = clients/'.build/native-interop/caddy_destination.rs'
s = bridge.read_text()
assert s.count('mod nf_support;') == 1
s = s.replace('mod nf_support;', 'mod nf_support;\n#[path = '+json.dumps(str(clients/'scripts/native-bulk-services.rs'))+']\nmod bulk;')
marker = 'let mut tasks = vec![tokio::spawn(async move { memory.run(incoming, output).await })];'
assert s.count(marker) == 1
s = s.replace(marker, marker+'\n    tasks.extend(bulk::start(&stack));')
bridge.write_text(s)
assert (a.baseline/'native_audit_test.go').read_bytes() == (a.candidate/'native_audit_test.go').read_bytes()
print('Identical Caddy fixture; unchanged protocol code and shared bounded destination services.')
