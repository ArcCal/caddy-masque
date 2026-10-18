//! Production NF protocols and SOCKS against Caddy. The client's existing
//! test bridge supplies verified Rust TLS/QUIC, not Apple Network.framework.
mod nf_support;
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use masque_nf_core::{client::Client, native::OPEN_TCP, socks};
use masque_vpn::netstack::NetStack;
use nf_support::{Backend, Server, TARGET4, TARGET6};
use std::{net::{IpAddr, SocketAddr}, path::PathBuf, sync::Arc, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpStream, UdpSocket, UnixDatagram}, sync::mpsc};

async fn within<T>(future: impl std::future::Future<Output = T>) -> Result<T> {
    Ok(tokio::time::timeout(Duration::from_secs(20), future).await?)
}

// A deterministic destination behind Caddy's channel-backed TUN, including
// actual TCP/IP, UDP and DNS. Only the host network is simulated.
async fn destination(path: &str) -> Result<Vec<tokio::task::JoinHandle<()>>> {
    let socket = Arc::new(UnixDatagram::bind(format!("{path}.peer"))?);
    socket.connect(path)?;
    let stack = NetStack::new(0);
    stack.set_addresses(&[TARGET4.parse()?, TARGET6.parse()?]);
    let (input, incoming) = mpsc::channel(1024);
    let (output, mut outgoing) = mpsc::channel::<Bytes>(1024);
    let memory = stack.clone();
    let mut tasks = vec![tokio::spawn(async move { memory.run(incoming, output).await })];
    let receive = socket.clone();
    tasks.push(tokio::spawn(async move {
        let mut packet = vec![0; 65535];
        while let Ok(n) = receive.recv(&mut packet).await {
            if input.send(Bytes::copy_from_slice(&packet[..n])).await.is_err() { break; }
        }
    }));
    tasks.push(tokio::spawn(async move {
        while let Some(packet) = outgoing.recv().await { if socket.send(&packet).await.is_err() { break; } }
    }));
    let mut listener = stack.listen(7, 32)?;
    tasks.push(tokio::spawn(async move {
        while let Ok(connection) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = tokio::io::split(connection);
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    }));
    let udp = stack.bind_udp(7)?;
    tasks.push(tokio::spawn(async move {
        while let Ok((packet, peer)) = udp.recv_from().await { let _ = udp.send_to(&packet, peer).await; }
    }));
    let dns = stack.bind_udp(53)?;
    tasks.push(tokio::spawn(async move {
        while let Ok((query, peer)) = dns.recv_from().await {
            if let Some(answer) = nf_support::caddy_dns_answer(&query) { let _ = dns.send_to(&answer, peer).await; }
        }
    }));
    Ok(tasks)
}

fn address(destination: &str) -> Vec<u8> {
    match destination.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => [&[1][..], &ip.octets()].concat(),
        Ok(IpAddr::V6(ip)) => [&[4][..], &ip.octets()].concat(),
        Err(_) => [&[3, destination.len() as u8][..], destination.as_bytes()].concat(),
    }
}

async fn request(proxy: SocketAddr, command: u8, destination: &str, port: u16) -> Result<(TcpStream, u8, SocketAddr)> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0; 2]; stream.read_exact(&mut method).await?;
    ensure!(method == [5, 0], "NF SOCKS authentication negotiation changed");
    let mut wire = vec![5, command, 0]; wire.extend(address(destination)); wire.extend(port.to_be_bytes());
    stream.write_all(&wire).await?;
    let mut head = [0; 4]; stream.read_exact(&mut head).await?;
    ensure!(head[0] == 5 && head[2] == 0);
    let ip = match head[3] {
        1 => { let mut a = [0; 4]; stream.read_exact(&mut a).await?; IpAddr::from(a) },
        4 => { let mut a = [0; 16]; stream.read_exact(&mut a).await?; IpAddr::from(a) },
        _ => anyhow::bail!("invalid NF SOCKS response address"),
    };
    let port = stream.read_u16().await?;
    Ok((stream, head[1], SocketAddr::new(ip, port)))
}

async fn tcp_echo(proxy: SocketAddr, target: &str) -> Result<()> {
    let (mut stream, code, _) = within(request(proxy, 1, target, 7)).await??;
    ensure!(code == 0, "NF SOCKS TCP {target} refused with {code}");
    let data: Vec<u8> = (0..100_013).map(|i| (i % 251) as u8).collect();
    let (mut read, mut write) = stream.split();
    let sent = data.clone();
    let ((), received) = within(async {
        let send = async { write.write_all(&sent).await?; write.shutdown().await?; Ok::<_, anyhow::Error>(()) };
        let receive = async { let mut data = Vec::new(); read.read_to_end(&mut data).await?; Ok::<_, anyhow::Error>(data) };
        tokio::try_join!(send, receive)
    }).await??;
    ensure!(received == data, "NF TCP bytes or half-close changed for {target}");
    Ok(())
}

async fn udp_echo(proxy: SocketAddr, target: &str, payload_len: usize, family: &str) -> Result<()> {
    let (control, code, relay) = within(request(proxy, 3, "0.0.0.0", 0)).await??;
    ensure!(code == 0, "NF UDP ASSOCIATE refused");
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
    let mut wire = vec![0, 0, 0]; wire.extend(address(target)); wire.extend(7u16.to_be_bytes()); wire.extend(&payload);
    socket.send_to(&wire, relay).await?;
    let mut incoming = vec![0; 2048]; let (n, peer) = within(socket.recv_from(&mut incoming)).await??;
    ensure!(peer == relay && n >= 10 && incoming[..3] == [0, 0, 0], "NF UDP response peer/reserved/fragment fields changed");
    let (source, offset) = match incoming[3] {
        1 => (IpAddr::from(<[u8; 4]>::try_from(&incoming[4..8])?), 8),
        4 if n >= 22 => (IpAddr::from(<[u8; 16]>::try_from(&incoming[4..20])?), 20),
        _ => anyhow::bail!("NF UDP response has an invalid address family"),
    };
    if let Ok(requested) = target.parse::<IpAddr>() { ensure!(source == requested, "NF UDP literal destination changed"); }
    else { ensure!(source == TARGET4.parse::<IpAddr>()? || (family == "dual-stack" && source == TARGET6.parse::<IpAddr>()?), "NF UDP domain response is outside the controlled DNS answers"); }
    ensure!(n == offset + 2 + payload.len() && incoming[offset..offset+2] == 7u16.to_be_bytes() && incoming[offset+2..n] == payload,
        "NF UDP response length, port or payload changed for {target}");
    drop(control);
    Ok(())
}

async fn case(server: &Server, mode: &str, family: &str, limit: Option<usize>, stream_zero: bool, stable: bool) -> Result<()> {
    let mut backend = Backend::with_options(server, limit, stream_zero);
    let mut config = server.config(if mode == "h3-capsules" { "h3" } else { mode });
    config.server_name = Some("vpn.test".into()); config.username = "alice".into(); config.password = "correct horse battery".into();
    let client = Client::new(&config, backend.bridge.clone())?;
    let listener = backend.bridge.listen("127.0.0.1:0".parse()?).await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move { socks::run(&client, vec![listener], socks::Settings { dns: config.dns, credentials: None }).await });
    backend.connected().await;
    let expected = match mode { "h2" => "HTTP/2", "http/1.1" => "HTTP/1.1", _ => "HTTP/3" };
    ensure!(backend.status.borrow().1 == expected, "NF selected unexpected transport: {:?}", backend.status.borrow());
    for target in [TARGET4, "echo.test.invalid"] {
        tcp_echo(address, target).await.with_context(|| format!("NF {mode} {family} TCP {target}"))?;
        let payload = if target == "echo.test.invalid" && family == "dual-stack" { 1232 } else { 1252 };
        udp_echo(address, target, payload, family).await.with_context(|| format!("NF {mode} {family} UDP {target}"))?;
    }
    if family == "dual-stack" {
        tcp_echo(address, TARGET6).await.context("NF IPv6 TCP")?;
        udp_echo(address, TARGET6, 1232, family).await.context("NF IPv6 UDP")?;
    }
    else { let (_, code, _) = within(request(address, 1, TARGET6, 7)).await??; ensure!(code == 3, "IPv4-only NF tunnel did not refuse IPv6"); }
    if stable { tokio::time::sleep(Duration::from_secs(12)).await; udp_echo(address, TARGET4, 1252, family).await?; }
    if mode == "h3-capsules" || limit.is_some_and(|n| n < 1289) {
        ensure!(backend.datagrams_sent() == 0, "NF Capsule selection emitted native DATAGRAMs");
    } else if mode == "h3" || mode == "auto" { ensure!(backend.datagrams_sent() > 0, "NF datagram control never used native DATAGRAMs"); }
    if expected == "HTTP/3" { ensure!(backend.opened.lock().unwrap().iter().all(|(kind, _)| *kind != OPEN_TCP), "forced NF HTTP/3 fell back to TCP"); }
    ensure!(backend.opened.lock().unwrap().len() == 1 && backend.status.borrow().1 == expected,
        "NF reconnected or changed transport during the established session");
    task.abort(); let _ = task.await;
    drop(backend);
    within(async { loop { if std::net::TcpListener::bind(address).is_ok() { break; } tokio::time::sleep(Duration::from_millis(10)).await; } }).await?;
    println!("PASS NF {mode} {family} capacity={limit:?} idle-stream-zero={stream_zero}: verified transport, DNS, TCP half-close/100013 bytes, UDP full1280-byte IP packets, family isolation, cancellation");
    Ok(())
}

async fn refusal(server: &Server, mode: &str) -> Result<()> {
    let backend = Backend::start(server);
    let mut config = server.config(if mode == "h3-capsules" { "h3" } else { mode });
    config.server_name = Some("vpn.test".into()); config.username = "alice".into(); config.password = "incorrect-test-password".into();
    let client = Client::new(&config, backend.bridge.clone())?;
    let listener = backend.bridge.listen("127.0.0.1:0".parse()?).await?;
    let result = within(socks::run(&client, vec![listener], socks::Settings { dns: config.dns, credentials: None })).await?;
    let error = result.expect_err("NF accepted wrong server credentials");
    let expected = if mode == "http/1.1" { "200 OK" } else { "404 Not Found" };
    ensure!(format!("{error:#}").contains(expected), "NF refusal did not carry expected {expected}: {error:#}");
    ensure!(backend.status.borrow().0 != 1, "NF declared connected with wrong credentials");
    println!("PASS NF {mode} wrong credentials: {expected}, no connected state");
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 6, "usage: caddy-nf-compat PORT CA_FILE MODE SERVER_FAMILY HOST_SOCKET");
    let server = Server::for_caddy(format!("127.0.0.1:{}", args[1]).parse()?, PathBuf::from(&args[2]));
    let tasks = destination(&args[5]).await?;
    case(&server, &args[3], &args[4], None, false, true).await?;
    refusal(&server, &args[3]).await?;
    if args[3] == "h3" {
        case(&server, "auto", &args[4], None, false, false).await?;
        for limit in [0, 1168, 1172, 1288, 1289] { case(&server, "h3", &args[4], Some(limit), false, false).await?; }
        case(&server, "h3", &args[4], Some(1168), true, false).await?;
    }
    for task in tasks { task.abort(); }
    Ok(())
}
