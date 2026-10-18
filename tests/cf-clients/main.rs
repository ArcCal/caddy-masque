//! Exercise the CF gateway's unchanged generic client library, not its private WARP dialect.
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use masque_frontend::client::{Client, Host, TunnelState};
use masque_frontend::config::{ClientConfig, Password};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch, Notify};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

#[derive(Default)]
struct Events { configurations: AtomicUsize, errors: Mutex<Vec<String>>, failed: Notify }
struct EventsLayer(Arc<Events>);
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EventsLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Message<'a>(&'a Events);
        impl tracing::field::Visit for Message<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    let message = format!("{value:?}");
                    if message.starts_with("session failed:") {
                        self.0.errors.lock().unwrap().push(message);
                        self.0.failed.notify_one();
                    }
                }
            }
        }
        event.record(&mut Message(&self.0));
    }
}
struct TestHost { state: watch::Sender<Option<TunnelState>>, events: Arc<Events> }
impl Host for TestHost {
    fn configure(&mut self, state: &TunnelState) -> Result<()> {
        self.state.send_replace(Some(state.clone()));
        self.events.configurations.fetch_add(1, Ordering::Release);
        Ok(())
    }
}
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task { fn drop(&mut self) { self.0.abort(); } }
struct Vpn {
    client: Arc<Client>, task: Task, events: Arc<Events>, state: watch::Receiver<Option<TunnelState>>,
    outgoing: mpsc::Sender<Bytes>, incoming: mpsc::Receiver<Bytes>,
}
impl Vpn {
    async fn start(config: &ClientConfig, server: SocketAddr) -> Result<Self> {
        let config = config.clone();
        let client = Arc::new(tokio::task::spawn_blocking(move || Client::new(&config, vec![server], None)).await??);
        let (outgoing, mut from_host) = mpsc::channel(64);
        let (to_host, incoming) = mpsc::channel(64);
        let (state_tx, state) = watch::channel(None);
        let events = Arc::new(Events::default());
        let observed = events.clone(); let running = client.clone();
        let mut host = TestHost { state: state_tx, events: events.clone() };
        let task = Task(tokio::spawn(async move {
            running.run(&mut host, to_host, &mut from_host)
                .with_subscriber(tracing_subscriber::registry().with(EventsLayer(observed))).await;
        }));
        Ok(Self { client, task, events, state, outgoing, incoming })
    }
    async fn established(&mut self, dual_stack: bool) -> Result<(Ipv4Addr, Option<Ipv6Addr>)> {
        let state = tokio::time::timeout(Duration::from_secs(20), self.state.wait_for(Option::is_some)).await??.clone().unwrap();
        ensure!(state.full_tunnel && !state.routes.is_empty(), "missing full-tunnel routes");
        let v4 = state.addresses.iter().find_map(|p| match p.addr() { IpAddr::V4(ip) => Some(ip), _ => None }).context("no IPv4 assignment")?;
        let v6 = state.addresses.iter().find_map(|p| match p.addr() { IpAddr::V6(ip) => Some(ip), _ => None });
        ensure!(v6.is_some() == dual_stack, "address families differ from configured client/server capability");
        Ok((v4, v6))
    }
    async fn echo(&mut self, source: IpAddr, length: usize, sequence: u32) -> Result<()> {
        let packet = udp(source, length, sequence);
        let mut payload = vec![0]; payload.extend_from_slice(&packet);
        self.outgoing.send(Bytes::from(payload)).await?;
        let received = tokio::time::timeout(Duration::from_secs(8), self.incoming.recv()).await?.context("packet channel closed")?;
        ensure!(received.len() == length && received[0] >> 4 == packet[0] >> 4, "inner packet length/version changed");
        let offset = match source {
            IpAddr::V4(source) => { ensure!(received[12..16] == [198,51,100,7] && received[16..20] == source.octets(), "IPv4 reply addresses changed"); 20 },
            IpAddr::V6(source) => { ensure!(received[8..24] == "2001:db8::7".parse::<Ipv6Addr>()?.octets() && received[24..40] == source.octets(), "IPv6 reply addresses changed"); 40 },
        };
        ensure!(received[offset..offset+2] == 7u16.to_be_bytes() && received[offset+2..offset+4] == 50000u16.to_be_bytes(), "UDP reply ports changed");
        ensure!(received[offset+8..] == packet[offset+8..], "UDP echo payload corrupted");
        Ok(())
    }
    async fn rejected(&self) -> Result<Vec<String>> {
        tokio::time::timeout(Duration::from_secs(15), self.events.failed.notified()).await?;
        ensure!(self.state.borrow().is_none(), "rejected identity configured host state");
        Ok(self.events.errors.lock().unwrap().clone())
    }
    async fn stop(mut self) { self.task.0.abort(); let _ = (&mut self.task.0).await; self.client.close().await; }
}
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32; let mut high = None;
    for part in parts { for &byte in *part { if let Some(first) = high.take() { sum += u16::from_be_bytes([first,byte]) as u32; } else { high = Some(byte); } } }
    if let Some(byte) = high { sum += u32::from(byte) << 8; }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}
fn udp(source: IpAddr, length: usize, sequence: u32) -> Vec<u8> {
    let header = if source.is_ipv4() { 20 } else { 40 };
    assert!(length >= header+12 && length <= 1350);
    let mut packet = vec![0x5a; length]; packet[..header+8].fill(0);
    let udp_len = length-header;
    match source {
        IpAddr::V4(source) => {
            packet[0] = 0x45; packet[2..4].copy_from_slice(&(length as u16).to_be_bytes()); packet[8] = 64; packet[9] = 17;
            packet[12..16].copy_from_slice(&source.octets()); packet[16..20].copy_from_slice(&[198,51,100,7]);
            let sum = checksum(&[&packet[..20]]); packet[10..12].copy_from_slice(&sum.to_be_bytes());
        },
        IpAddr::V6(source) => {
            packet[0] = 0x60; packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes()); packet[6] = 17; packet[7] = 64;
            packet[8..24].copy_from_slice(&source.octets()); packet[24..40].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        },
    }
    packet[header..header+2].copy_from_slice(&50000u16.to_be_bytes()); packet[header+2..header+4].copy_from_slice(&7u16.to_be_bytes());
    packet[header+4..header+6].copy_from_slice(&(udp_len as u16).to_be_bytes()); packet[header+8..header+12].copy_from_slice(&sequence.to_be_bytes());
    let len = (udp_len as u32).to_be_bytes(); let protocol = [0,0,0,17];
    let (src,dst) = if source.is_ipv4() { (&packet[12..16], &packet[16..20]) } else { (&packet[8..24], &packet[24..40]) };
    let sum = checksum(&[src,dst,&len,&protocol,&packet[header..]]);
    packet[header+6..header+8].copy_from_slice(&if sum == 0 { 0xffffu16 } else { sum }.to_be_bytes());
    packet
}
fn config(port: u16, ca: &Path, transport: &str, dual_stack: bool) -> Result<ClientConfig> {
    let mut config = ClientConfig::parse(&format!(r#"
uri_template = "https://vpn.test:{port}/.well-known/masque/ip/{{target}}/{{ipproto}}/"
username = "alice"
password = "correct horse battery"
server_name = "vpn.test"
transport = "{transport}"
ipv6 = {dual_stack}
mode = "system"
[tunnel]
mtu = 1350
"#))?;
    config.ca = Some(ca.to_owned()); Ok(config)
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 7, "usage: caddy-cf-frontend-compat PORT CA_FILE TRANSPORT SERVER_FAMILY WRONG_CA_FILE RECONNECT_MARKER");
    let port: u16 = args[1].parse()?; let ca = PathBuf::from(&args[2]); let transport = &args[3]; let dual_stack = args[4] == "dual-stack";
    let server: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let config = config(port, &ca, transport, dual_stack)?;
    let mut vpn = Vpn::start(&config, server).await?;
    let (source4, source6) = vpn.established(dual_stack).await?;
    vpn.echo(IpAddr::V4(source4), 1350, 0).await?;
    if let Some(source) = source6 { vpn.echo(IpAddr::V6(source), 1280, 0).await?; vpn.echo(IpAddr::V6(source), 1350, 1).await?; }
    let mut wrong_password = config.clone(); wrong_password.password = Password::new("incorrect-test-password");
    let bad = Vpn::start(&wrong_password, server).await?;
    let errors = bad.rejected().await?;
    let refused = if transport == "http/1.1" { "200 OK" } else { "404 Not Found" };
    ensure!(errors.iter().any(|message| message.contains(refused)), "authentication refusal lost expected status: {:?}", errors);
    bad.stop().await;
    let mut wrong_ca = config.clone(); wrong_ca.ca = Some(PathBuf::from(&args[5]));
    let bad = Vpn::start(&wrong_ca, server).await?;
    let errors = bad.rejected().await?;
    ensure!(errors.iter().any(|message| message.contains("certificate") || message.contains("UnknownIssuer")), "wrong CA did not produce a certificate-verification failure: {:?}", errors);
    bad.stop().await;
    for sequence in 0..512 { vpn.echo(IpAddr::V4(source4), 1350, sequence+100).await?; }
    if let Some(source) = source6 { for sequence in 0..256 { vpn.echo(IpAddr::V6(source), 1350, sequence+100).await?; } }
    tokio::time::sleep(Duration::from_secs(12)).await;
    vpn.echo(IpAddr::V4(source4), 1350, 10000).await?;
    if let Some(source) = source6 { vpn.echo(IpAddr::V6(source), 1350, 10000).await?; }
    ensure!(vpn.events.configurations.load(Ordering::Acquire) == 1 && vpn.events.errors.lock().unwrap().is_empty(), "initial session failed or reconnected during the MTU-probe interval");
    // The Go fixture revokes then restores this credential after this marker.
    std::fs::write(&args[6], b"ready for credential-revocation reconnect")?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop { if vpn.events.configurations.load(Ordering::Acquire) >= 2 { break; } tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await.context("client did not automatically reconnect after credential restoration")?;
    ensure!(!vpn.events.errors.lock().unwrap().is_empty(), "reconnect did not observe the revoked session ending");
    let (source4,source6) = vpn.established(dual_stack).await?;
    vpn.echo(IpAddr::V4(source4), 1350, 20000).await?;
    if let Some(source) = source6 { vpn.echo(IpAddr::V6(source), 1350, 20000).await?; }
    vpn.stop().await;
    println!("PASS CF generic frontend {} {}: verified TLS, auth refusal/isolation, address/routes, 512 IPv4 full-MTU echoes, IPv6 1280/full-MTU and 256 echoes when enabled, MTU probe stability, automatic reconnect after revocation, cancellation", transport, args[4]);
    Ok(())
}
