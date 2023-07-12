use serde::Deserialize;
use std::{path::PathBuf, net::{SocketAddr, IpAddr}};

/// Root configuration for ptproxy.
#[derive(Deserialize, Debug)]
pub struct Config {
	/// Bind settings for the QUIC (public) endpoint.
	/// **Default:** port 11011 at wildcard address
	pub endpoint: Option<BindSettings>,

	/// Bind settings for the HTTP/1.1 (private) endpoint.
	/// **Default:** port 11080 at localhost address
	pub private_endpoint: Option<BindSettings>,

	/// TLS settings for the QUIC endpoint.
	/// **Required**
	pub tls: TLS,

	/// Peer(s) to establish QUIC connections with.
	/// **Required**
	pub peer: Vec<Peer>,

	/// HTTP/1.1 upstream to proxy requests received through server-mode peers to.
	/// **Required** if there are peers with `mode` set to `Server`.
	pub upstream: Upstream,
}

/// Location to bind an endpoint (UDP or TCP) at.
#[derive(Deserialize, Debug)]
pub struct BindSettings {
	/// Address to bind the endpoint at.
	pub bind_address: Option<String>,

	/// Port to bind the endpoint at.
	pub bind_port: Option<u16>,
}

impl BindSettings {
	fn parse(&self, fallback: SocketAddr) -> Result<SocketAddr, Box<dyn std::error::Error>> {
		let ip = match self.bind_address {
			Some(addr) => addr.parse()?,
			None => fallback.ip(),
		};
		let port = self.bind_port.unwrap_or(fallback.port());
		Ok(SocketAddr::new(ip, port))
	}
}

/// TLS identity settings for the QUIC endpoint.
#[derive(Deserialize, Debug)]
pub struct TLS {
	/// CA file to verify the certificate of the peer against.
	/// **Default:** use system root CA store
	pub ca: Option<PathBuf>,

	/// Skip verification of the peer certificate. **Dangerous.**
	/// **Default:** false
	#[serde(default)]
	pub skip_verify: bool,

	/// Path to certificate to present to peers.
	/// **Required**
	pub cert: PathBuf,

	/// Path to certificate's private key.
	/// **Required**
	pub key: PathBuf,
}

/// Definition of a peer to establish a connection with, and configuration of that connection's [transport](quinn::TransportConfig`).
///
/// Except for `hostname` and `mode`, which must be *opposite* at each end (and possibly `connect_url`),
/// the transport parameters are usually kept identical on both sides.
#[derive(Deserialize, Debug)]
pub struct Peer {
	/// Hostname to match in the other peer's certificate.
	/// Each peer must have a unique `(hostname, mode)` tuple.
	/// **Required**
	pub hostname: String,

	/// Whether to connect to the target peer (`Client`), or accept connections from it (`Server`).
	/// Each peer must have a unique `(hostname, mode)` tuple.
	/// **Required**
	pub mode: PeerMode,

	/// Hostname and port to connect to, in `host:port` form.
	/// Ignored if `mode` is not `Client`.
	/// **Default:** use this peer's `hostname`, and the same port the QUIC endpoint is bound at.
	pub connect_url: Option<String>,

	/// Time to wait since last connection attempt (or death of connection) before attempting a new connection, in milliseconds.
	/// **Default:** 2000
	#[serde(default = "default_connect_interval")]
	pub connect_interval: u64,

	/// Maximum duration of inactivity to accept before considering the connection dead, in milliseconds.
	/// The true idle timeout is the minimum of this and the peer’s own max idle timeout.
	/// See [`quinn::TransportConfig::max_idle_timeout`].
	/// **Default:** 5000
	#[serde(default = "default_max_idle_timeout")]
	pub max_idle_timeout: u64,

	/// Initial estimate of RTT with the peer, in milliseconds.
	/// This is the value used before an RTT sample is taken.
	/// See [`quinn::TransportConfig::initial_rtt`].
	/// **Default:** see quinn documentation (no estimate)
	pub initial_rtt: Option<u64>,

	/// Size of the initial congestion window, in bytes.
	/// See [`quinn::congestion::CubicConfig::initial_window`].
	/// **Default:** see quinn documentation (usually 14720 bytes)
	pub initial_window: Option<u64>,

	/// Algorithm to use for the congestion controller.
	/// **Default:** Cubic
	#[serde(default)]
	pub congestion_algorithm: CongestionAlgorithm,
}

#[derive(Deserialize, Debug)]
pub struct Upstream {
	/// Hostname and port to connect to, in `host:port` form.
	/// **Required**
	pub url: String,
}

#[derive(Deserialize, Debug)]
pub enum PeerMode {
	Client,
	Server,
}

#[derive(Deserialize, Debug)]
pub enum CongestionAlgorithm {
	/// See [`quinn::congestion::Bbr`].
	Bbr,
	/// See [`quinn::congestion::Cubic`].
	Cubic,
	/// See [`quinn::congestion::NewReno`].
	NewReno,
}

impl Default for CongestionAlgorithm {
	fn default() -> Self {
		CongestionAlgorithm::Cubic
	}
}

fn default_max_idle_timeout() -> u64 {
	5000
}

fn default_connect_interval() -> u64 {
	2000
}
