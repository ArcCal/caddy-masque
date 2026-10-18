
// Appended to a temporary copy of the current client's unchanged test host.
// Only connect that host to Caddy and expose its deterministic DNS fixture;
// do not launch the Rust reference server or replace production NF protocols.
impl Server {
    pub fn for_caddy(address: SocketAddr, ca: PathBuf) -> Self {
        Self { _dir: tempfile::tempdir().unwrap(), address, ca, tasks: Vec::new() }
    }
}
pub fn caddy_dns_answer(query: &[u8]) -> Option<Vec<u8>> { dns_answer(query) }
