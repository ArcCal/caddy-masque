#!/usr/bin/env python3
"""Compare two actual Caddy peers with one unchanged native client."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['clients', 'client', 'baseline', 'candidate', 'destination', 'logs']:
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--trust-cleanup', type=Path)
    p.add_argument('--portable', action='store_true')
    p.add_argument('--control', action='store_true')
    p.add_argument('--reverse', action='store_true')
    p.add_argument('--mib', type=int, choices=range(1,129), default=32)
    p.add_argument('--warmup-mib', type=int, choices=range(1,17), default=8)
    p.add_argument('--rounds', type=int, choices=[1,2,4,8], default=4)
    a = p.parse_args()
    if not a.portable:
        assert platform.system() == 'Darwin' and platform.machine() == 'arm64'
        assert os.environ.get('GITHUB_ACTIONS') == 'true' and a.trust_cleanup
    a.logs.mkdir(parents=True, exist_ok=False)
    helpers = runpy.run_path(str(a.clients/'masque-nf-headless/test-native-tunnel.py'))
    runtime = runpy.run_path(str(a.clients/'scripts/test-native-regression.py'))
    measure = runpy.run_path(str(a.clients/'scripts/test-native-streaming.py'))['measure']
    binaries = {'baseline': a.baseline.resolve(), 'candidate': (a.baseline if a.control else a.candidate).resolve()}
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report = {'scope': 'Portable harness preflight' if a.portable else 'Actual Network.framework client against Caddy',
              'server_sha256': {label:digest(path) for label,path in binaries.items()},
              'client_sha256':digest(a.client), 'destination_sha256':digest(a.destination),
              'control':a.control, 'mib':a.mib, 'warmup_mib':a.warmup_mib, 'rounds':a.rounds,
              'limits':['Loopback and shared simulated destination; no WAN claim',
                        'Timed payload includes verified EOF; no discarded observations',
                        'Server CPU covers Go peer; destination process is separate',
                        'RSS is sampled, not peak'], 'trials':[]}
    peers = {}; anchors = []; handles = []
    try:
        for label,binary in binaries.items():
            log = (a.logs/(label+'-peer.log')).open('w'); handles.append(log)
            env = os.environ.copy(); env['AUDIT_DESTINATION']=str(a.destination.resolve())
            peer = subprocess.Popen([str(binary), '-test.run=^TestNativeAuditPeer$', '-test.timeout=45m'],
                                    env=env, stdout=subprocess.PIPE, stderr=log, bufsize=0)
            peers[label] = (peer, None)
            info = helpers['peer_info'](peer)
            peers[label] = (peer, info)
            if not a.portable:
                cert = info['certificate']; der = a.logs/(label+'-anchor.der')
                subprocess.run(['openssl','x509','-in',cert,'-outform','DER','-out',str(der)],check=True)
                fp = subprocess.check_output(['openssl','x509','-in',cert,'-noout','-fingerprint','-sha1'],text=True).strip().split('=',1)[1].replace(':','')
                subprocess.run(['sudo','-n','security','add-trusted-cert','-d','-r','trustRoot','-k','/Library/Keychains/System.keychain',cert],check=True,timeout=30)
                anchors.append((der,fp))
        transports = ['h2','h3']; modes = ['download','upload','duplex']
        if a.reverse: transports.reverse(); modes.reverse()
        for transport in transports:
            for mode in modes:
                for number in range(a.rounds):
                    order = ['baseline','candidate','candidate','baseline']
                    if number % 2: order = ['candidate','baseline','baseline','candidate']
                    for position,label in enumerate(order):
                        peer,info = peers[label]
                        directory = a.logs/f'{transport}-{mode}-{number+1}-{position+1}-{label}'
                        directory.mkdir()
                        port = runtime['unused_port'](); config = directory/'client.toml'; log = directory/'client.log'
                        text = (f'uri_template = "https://{info["address"]}/.well-known/masque/ip/{{target}}/{{ipproto}}/"\n'
                                f'server_name = "{info["server_name"]}"\nusername = "{info.get("username","test")}"\n'
                                f'password = "{info["password"]}"\ntransport = "{transport}"\n'
                                f'dns = ["{info["ipv4"]}"]\nmode = "socks"\n[socks]\nlisten = ["127.0.0.1:{port}"]\n')
                        if a.portable: text = 'ca = '+json.dumps(info['certificate'])+'\nipv6 = false\n'+text
                        config.write_text(text)
                        command = [str(a.client.resolve()), '-c', str(config)]
                        if not a.portable: command += ['--log-level','normal']
                        env = os.environ.copy(); env['RUST_LOG']='info'
                        with log.open('w') as output:
                            client = subprocess.Popen(command,env=env,stdout=output,stderr=output)
                            try:
                                runtime['wait_for'](lambda:runtime['up_count'](log)>0,client,log,40)
                                expected={'h2':'HTTP/2','h3':'HTTP/3'}[transport]
                                assert f'transport="{expected}"' in log.read_text(), log.read_text()
                                up = runtime['up_count'](log)
                                metrics=measure(a,info,mode,port,client.pid,peer.pid)
                                assert runtime['up_count'](log)==up, 'Unexpected reconnect during measurement'
                            finally:
                                runtime['stop'](client)
                        row={'transport':transport,'mode':mode,'round':number+1,'position':position+1,'build':label,'clean_exit':True,**metrics}
                        report['trials'].append(row)
                        (a.logs/'report.json').write_text(json.dumps(report,indent=2)+'\n')
                        print(json.dumps(row),flush=True)
        assert len(report['trials']) == 2*3*a.rounds*4
        report['all_trials_complete']=True
    finally:
        failures=[]
        for der,fp in reversed(anchors):
            try:
                try: subprocess.run(['sudo','-n',str(a.trust_cleanup.resolve()),str(der)],check=True,timeout=30)
                finally: subprocess.run(['sudo','-n','security','delete-certificate','-Z',fp,'/Library/Keychains/System.keychain'],check=True,timeout=30)
            except Exception as error: failures.append(str(error))
        for peer,_ in peers.values():
            try: runtime['stop'](peer)
            except Exception as error: failures.append(str(error))
        for log in handles: log.close()
        report['cleanup_errors']=failures
        (a.logs/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        assert not failures, failures

if __name__ == '__main__':
    main()
