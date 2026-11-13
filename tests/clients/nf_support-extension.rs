
// Appended to a temporary copy of the current client's unchanged test host.
// Only connect that host to Caddy and expose its deterministic DNS fixture;
// do not launch the Rust reference server or replace production NF protocols.
impl Server {
    pub fn for_caddy(address: SocketAddr, ca: PathBuf) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config: ServerConfig = toml::from_str(&format!(
            "state_dir = {:?}\n[tls]\ncert = 'unused'\nkey = 'unused'\n[tunnel]\nipv4 = '10.89.0.1/24'\n[network]\nmanage = false\n", dir.path().join("state")
        )).unwrap();
        let (sender, _receiver) = mpsc::channel(1);
        let proxy = Proxy::with_forget(&config, sender, Arc::new(|_| Ok(0))).unwrap();
        Self { _dir: dir, address, ca, proxy, forwarded: Arc::new(AtomicUsize::new(0)), tasks: Vec::new() }
    }
}
pub fn caddy_dns_answer(query: &[u8]) -> Option<Vec<u8>> { dns_answer(query) }
