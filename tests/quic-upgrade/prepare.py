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
    fixture = server/'native_audit_test.go'
    go = fixture.read_text()
    source = (server/'masque_client_interop_test.go').read_text()
    start = source.index('func newTestChain(')
    chain = source[start:source.index('\n}\n', start)+3]
    chain = chain.replace('func newTestChain(', 'func nativeAuditChain(', 1)
    chain = chain.replace('t.Helper()', 't.Helper()\n\tserial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))\n\tif err != nil { t.Fatal(err) }\n\tserial.Add(serial, big.NewInt(1))', 1)
    chain = chain.replace('SerialNumber:          big.NewInt(1)', 'SerialNumber:          serial', 1)
    chain = chain.replace('CommonName: "Test CA"', 'CommonName: fmt.Sprintf("Native audit CA %x", serial.Bytes())', 1)
    imports = ['crypto/ecdsa', 'crypto/elliptic', 'crypto/rand', 'crypto/x509', 'crypto/x509/pkix', 'encoding/pem', 'math/big']
    go = go.replace('import (', 'import (\n'+''.join('    '+json.dumps(x)+'\n' for x in imports), 1)
    go = go.replace('cert, ca := newTestChain(t)', 'cert, ca := nativeAuditChain(t)', 1)
    go = go.replace('256 << 10', '4 << 20')
    fixture.write_text(go+'\n'+chain)
bridge = clients/'.build/native-interop/caddy_destination.rs'
s = bridge.read_text()
assert s.count('mod nf_support;') == 1
s = s.replace('mod nf_support;', 'mod nf_support;\n#[path = '+json.dumps(str(clients/'scripts/native-bulk-services.rs'))+']\nmod bulk;')
marker = 'let mut tasks = vec![tokio::spawn(async move { memory.run(incoming, output).await })];'
assert s.count(marker) == 1
s = s.replace(marker, marker+'\n    tasks.extend(bulk::start(&stack));')
marker = 'socket.connect(path)?;'
assert s.count(marker) == 1
# Darwin's small default Unix datagram receive queue distorts bulk measurements.
# Reuse the existing SO_RCVBUF tuner without changing production dependencies.
s = s.replace(marker, marker+'\n    masque_vpn::quic::tune_udp_receive_buffer((&*socket).into());')
bridge.write_text(s)
assert (a.baseline/'native_audit_test.go').read_bytes() == (a.candidate/'native_audit_test.go').read_bytes()
print('Identical Caddy fixture; unchanged protocol code and shared bounded destination services.')
