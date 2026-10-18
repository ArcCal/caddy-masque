//! Portable interoperability of current app settings, packet APIs and SOCKS
//! wrappers with real Caddy. Host channels replace only native utun/routing/PF.
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use masque_vpn::client::{Client, Host, TunnelState};
use masque_vpn::config::{ClientConfig, Password};
use masque_vpn_killswitch as ks;
use masque_vpn_mac as mac;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch, Notify};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

#[derive(Clone, Copy, Debug)]
enum App { Mac, Killswitch }

impl App {
    fn config(self, port: u16, transport: &str, mode: &str) -> Result<ClientConfig> {
        let settings = format!(r#"{{"domain":"vpn.test:{port}","server_ip":"127.0.0.1","username":"alice","password":"correct horse battery","transport":"{transport}","mode":"{mode}","dns":["198.51.100.53"],"socks_listen":"127.0.0.1:1080"}}"#);
        let config = match self {
            Self::Mac => { let s = mac::config::Settings::parse(settings.as_bytes())?; ensure!(s.vpn_enabled() == (mode == "both") && s.socks_enabled()); s.client_config()? }
            Self::Killswitch => { let s = ks::config::Settings::parse(settings.as_bytes())?; ensure!(s.vpn_enabled() == (mode == "both") && s.socks_enabled()); s.client_config()? }
        };
        ensure!(!config.ipv6 && config.tunnel.mtu == 1350);
        Ok(config)
    }
    fn encapsulate(self, packet: &[u8]) -> Bytes { match self { Self::Mac => mac::packet::encapsulate_ipv4(packet), Self::Killswitch => ks::packet::encapsulate_ipv4(packet) }.expect("valid IPv4") }
    fn dns(self, source: Ipv4Addr) -> Bytes { match self { Self::Mac => mac::packet::dns_probe(source, Ipv4Addr::new(198,51,100,53), 0xcafe), Self::Killswitch => ks::packet::dns_probe(source, Ipv4Addr::new(198,51,100,53), 0xcafe) } }
    fn dns_reply(self, packet: &[u8], source: Ipv4Addr) -> bool { match self { Self::Mac => mac::packet::is_dns_probe_reply(packet, source, Ipv4Addr::new(198,51,100,53), 0xcafe), Self::Killswitch => ks::packet::is_dns_probe_reply(packet, source, Ipv4Addr::new(198,51,100,53), 0xcafe) } }
}

#[derive(Default)]
struct Events { up: std::sync::atomic::AtomicUsize, errors: std::sync::Mutex<Vec<String>>, notify: Notify }
struct EventsLayer(Arc<Events>);
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EventsLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Message<'a>(&'a Events);
        impl tracing::field::Visit for Message<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() != "message" { return; }
                let text = format!("{value:?}");
                if text == "tunnel up" { self.0.up.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                if text.starts_with("session failed:") { self.0.errors.lock().unwrap().push(text); self.0.notify.notify_one(); }
            }
        }
        event.record(&mut Message(&self.0));
    }
}
struct TestHost(watch::Sender<Option<TunnelState>>);
impl Host for TestHost { fn configure(&mut self, state: &TunnelState) -> Result<()> { self.0.send_replace(Some(state.clone())); Ok(()) } }
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task { fn drop(&mut self) { self.0.abort(); } }

struct Vpn { client: Arc<Client>, task: Task, outgoing: mpsc::Sender<Bytes>, incoming: mpsc::Receiver<Bytes>, state: watch::Receiver<Option<TunnelState>>, events: Arc<Events> }
impl Vpn {
    async fn start(config: &ClientConfig, server: SocketAddr) -> Result<Self> {
        let copied = config.clone();
        let client = Arc::new(tokio::task::spawn_blocking(move || Client::new(&copied, vec![server], None)).await??);
        let (outgoing, mut from_host) = mpsc::channel(64);
        let (to_host, incoming) = mpsc::channel(64);
        let (host_state, state) = watch::channel(None);
        let events = Arc::new(Events::default());
        let observed = events.clone();
        let running = client.clone();
        let task = Task(tokio::spawn(async move { running.run(&mut TestHost(host_state), to_host, &mut from_host).with_subscriber(tracing_subscriber::registry().with(EventsLayer(observed))).await; }));
        Ok(Self { client, task, outgoing, incoming, state, events })
    }
    async fn established(&mut self) -> Result<Ipv4Addr> {
        let state = tokio::time::timeout(Duration::from_secs(15), self.state.wait_for(Option::is_some)).await??.clone().unwrap();
        ensure!(state.full_tunnel && !state.addresses.is_empty() && state.addresses.iter().all(|ip| ip.is_ipv4()), "app must configure IPv4 only, even against dual-stack Caddy");
        match state.addresses[0].addr() { IpAddr::V4(source) => Ok(source), _ => unreachable!() }
    }
    async fn received(&mut self) -> Result<Bytes> { tokio::time::timeout(Duration::from_secs(10), self.incoming.recv()).await?.context("VPN packet channel closed") }
    async fn echo(&mut self, app: App, source: Ipv4Addr, length: usize, sequence: u32) -> Result<()> {
        let packet = udp(source, length, sequence);
        self.outgoing.send(app.encapsulate(&packet)).await?;
        let received = self.received().await?;
        ensure!(received.len() == length && received[0] >> 4 == 4, "IPv4 packet length or framing changed");
        ensure!(received[12..16] == [198,51,100,7] && received[16..20] == source.octets(), "IPv4 source/destination changed");
        ensure!(received[20..22] == 7u16.to_be_bytes() && received[22..24] == 50000u16.to_be_bytes(), "UDP ports changed");
        ensure!(received[28..] == packet[28..], "IPv4 echo payload corrupted");
        Ok(())
    }
    async fn stop(mut self) { self.task.0.abort(); let _ = (&mut self.task.0).await; self.client.close().await; }
}

fn checksum(packet: &mut [u8]) {
    packet[10] = 0; packet[11] = 0;
    let mut sum: u32 = packet[..20].as_chunks::<2>().0.iter().map(|word| u16::from_be_bytes(*word) as u32).sum();
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}
fn udp(source: Ipv4Addr, length: usize, sequence: u32) -> Vec<u8> {
    assert!(length >= 32);
    let mut packet = vec![0x5a; length];
    packet[..28].fill(0);
    packet[0] = 0x45; packet[2..4].copy_from_slice(&(length as u16).to_be_bytes()); packet[8] = 64; packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets()); packet[16..20].copy_from_slice(&[198,51,100,7]);
    packet[20..22].copy_from_slice(&50000u16.to_be_bytes()); packet[22..24].copy_from_slice(&7u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((length-20) as u16).to_be_bytes()); packet[28..32].copy_from_slice(&sequence.to_be_bytes()); checksum(&mut packet); packet
}

enum Traffic { Mac(Arc<mac::proxy::Traffic>), Killswitch(Arc<ks::proxy::Traffic>) }
impl Traffic { fn totals(&self) -> (u64,u64) { match self { Self::Mac(stats) => stats.totals(), Self::Killswitch(stats) => stats.totals() } } }
struct Socks { client: Arc<Client>, task: Task, stopped: Arc<Notify>, traffic: Traffic, control: tokio::net::TcpStream, socket: tokio::net::UdpSocket, address: SocketAddr, relay: SocketAddr }
impl Socks {
    async fn start(app: App, config: &ClientConfig, server: SocketAddr) -> Result<Self> {
        let copied = config.clone();
        let client = Arc::new(tokio::task::spawn_blocking(move || Client::new(&copied, vec![server], None)).await??);
        let stopped = Arc::new(Notify::new());
        let finished = stopped.clone(); let running = client.clone();
        let (address, traffic, task) = match app {
            App::Mac => {
                let listener = mac::proxy::listener("127.0.0.1:0".parse()?, None)?; let address = listener.local_addr()?;
                let traffic = Arc::new(mac::proxy::Traffic::default()); let stats = traffic.clone();
                let task = Task(tokio::spawn(async move { mac::proxy::run_counted(running, listener, vec![Ipv4Addr::new(198,51,100,53)], finished, stats).await.unwrap(); }));
                (address, Traffic::Mac(traffic), task)
            }
            App::Killswitch => {
                let listener = ks::proxy::listener("127.0.0.1:0".parse()?, None)?; let address = listener.local_addr()?;
                let traffic = Arc::new(ks::proxy::Traffic::default()); let stats = traffic.clone();
                let task = Task(tokio::spawn(async move { ks::proxy::run_counted(running, listener, vec![Ipv4Addr::new(198,51,100,53)], finished, stats).await.unwrap(); }));
                (address, Traffic::Killswitch(traffic), task)
            }
        };
        let mut control = tokio::net::TcpStream::connect(address).await?;
        control.write_all(&[5,1,0]).await?; let mut greeting = [0;2];
        tokio::time::timeout(Duration::from_secs(10), control.read_exact(&mut greeting)).await??; ensure!(greeting == [5,0]);
        control.write_all(&[5,3,0,1,0,0,0,0,0,0]).await?; let mut response = [0;10];
        tokio::time::timeout(Duration::from_secs(10), control.read_exact(&mut response)).await??; ensure!(response[..4] == [5,0,0,1]);
        let relay = SocketAddr::from((Ipv4Addr::new(response[4],response[5],response[6],response[7]), u16::from_be_bytes([response[8],response[9]])));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        Ok(Self { client, task, stopped, traffic, control, socket, address, relay })
    }
    async fn echo(&self, sequence: u32) -> Result<usize> {
        let mut request = vec![0,0,0,1,198,51,100,7,0,7]; request.extend_from_slice(&sequence.to_be_bytes()); request.extend_from_slice(b"concurrent wrapper SOCKS");
        self.socket.send_to(&request, self.relay).await?;
        let mut received = [0;1500]; let (length, from) = tokio::time::timeout(Duration::from_secs(10), self.socket.recv_from(&mut received)).await??;
        ensure!(from == self.relay && received[..length] == request, "SOCKS UDP echo payload or framing changed");
        Ok(request.len() - 10 + 28)
    }
    async fn stop(mut self) -> Result<()> {
        self.task.0.abort(); let _ = (&mut self.task.0).await;
        tokio::time::timeout(Duration::from_secs(2), self.stopped.notified()).await?;
        let mut byte = [0]; let closed = tokio::time::timeout(Duration::from_secs(2), self.control.read(&mut byte)).await?;
        ensure!(matches!(closed, Ok(0) | Err(_)), "SOCKS control stayed open after cancellation");
        ensure!(std::net::TcpListener::bind(self.address).is_ok() && std::net::UdpSocket::bind(self.relay).is_ok(), "SOCKS sockets not released after cancellation");
        self.client.close().await; Ok(())
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 6, "usage: caddy-wrapper-compat mac|killswitch PORT CA_FILE TRANSPORT SERVER_FAMILY");
    let app = match args[1].as_str() { "mac" => App::Mac, "killswitch" => App::Killswitch, _ => anyhow::bail!("unknown app") };
    let port: u16 = args[2].parse()?; let ca = PathBuf::from(&args[3]); let transport = &args[4];
    let server: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let mut config = app.config(port, transport, "both")?; config.ca = Some(ca.clone());
    let mut vpn = Vpn::start(&config, server).await?; let source = vpn.established().await?;
    vpn.outgoing.send(app.dns(source)).await?;
    ensure!(app.dns_reply(&vpn.received().await?, source), "wrapper DNS candidate probe failed through Caddy");
    vpn.echo(app, source, 1350, 0).await?;
    let mut bad_config = config.clone(); bad_config.password = Password::new("incorrect-test-password");
    let bad = Vpn::start(&bad_config, server).await?;
    tokio::time::timeout(Duration::from_secs(10), bad.events.notify.notified()).await?;
    // The fixture's website serves a 200 cover page. Refused HTTP/2 and HTTP/3
    // CONNECT requests retain its body but require a non-success status; a
    // refused HTTP/1.1 Upgrade can retain the website's ordinary 200 response.
    let refused = bad.events.errors.lock().unwrap().clone();
    let expected_status = if transport == "http/1.1" { "200 OK" } else { "404 Not Found" };
    ensure!(refused.iter().any(|message| message.contains(expected_status) && (message.contains("Capsule Protocol forbids") || message.contains("did not accept the CONNECT-IP request"))), "Caddy did not refuse bad credentials with the expected status {}: {:?}", expected_status, refused);
    ensure!(bad.state.borrow().is_none(), "bad credentials configured host networking"); bad.stop().await;
    vpn.echo(app, source, 1350, 1).await?;
    let mut socks_config = app.config(port, transport, "socks")?; socks_config.ca = Some(ca);
    let socks = Socks::start(app, &socks_config, server).await?;
    let mut expected_socks_bytes = 0;
    for sequence in 0..8 { let (vpn_result, socks_result) = tokio::join!(vpn.echo(app, source, 1350, sequence + 100), socks.echo(sequence)); vpn_result?; expected_socks_bytes += socks_result? as u64; }
    // Sequential full-MTU packets deliberately avoid depending on UDP queue
    // capacity or treating a dropped packet as successful throughput evidence.
    for sequence in 0..512 { vpn.echo(app, source, 1350, sequence + 1000).await?; }
    tokio::time::timeout(Duration::from_secs(2), async { loop { if socks.traffic.totals() == (expected_socks_bytes,expected_socks_bytes) { break; } tokio::task::yield_now().await; } }).await.context("wrapper SOCKS byte counters disagree with actual IP traffic")?;
    // Every mode waits beyond Caddy's 10-second dual-stack MTU-probe timeout.
    // The app still configures IPv4 only; the core must answer assigned-but-
    // unused IPv6 probes without reconnecting or exposing IPv6 to the host.
    tokio::time::sleep(Duration::from_secs(12)).await;
    vpn.echo(app, source, 1350, 99999).await?; let _ = socks.echo(99999).await?;
    ensure!(vpn.events.up.load(std::sync::atomic::Ordering::Relaxed) == 1 && vpn.events.errors.lock().unwrap().is_empty(), "primary VPN reconnected or failed across the probe interval");
    socks.stop().await?; vpn.echo(app, source, 1350, 100000).await?; vpn.stop().await;
    println!("PASS {:?} {} {}: settings, DNS, authentication isolation, concurrent VPN/SOCKS, 512 full-MTU bidirectional packets, IPv4 host state, probe stability, cancellation", app, transport, args[5]);
    Ok(())
}
