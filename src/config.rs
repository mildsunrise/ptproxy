use serde::Deserialize;
use std::{path::PathBuf, net::{IpAddr, SocketAddr}};

/// Root configuration for ptproxy.
#[derive(Deserialize, Debug)]
pub struct Config {
	/// Mode of operation and peer + upstream parameters.
	/// <br> **Required**
	pub general: GeneralConfig,

	/// TLS settings for the QUIC endpoint.
	/// <br> **Required**
	pub tls: TlsConfig,

	/// Transport parameters for the QUIC session with the peer.
	/// <br> **Optional**
	#[serde(default)]
	pub transport: TransportConfig,

	/// Limits, timeouts, intervals and other parameters that affect operation of ptproxy.
	/// <br> **Optional**
	#[serde(default)]
	pub system: SystemConfig,
}

/// Parameters describing general proxy operation: mode, and connection details
/// for the other peer and the source / target for HTTP/1.1 requests.
#[derive(Deserialize, Debug)]
pub struct GeneralConfig {
	/// Whether to connect to the target peer (`Client`), or accept connections from it (`Server`).
	/// <br> **Required**
	pub mode: PeerMode,

	/// Hostname to match in the other peer's certificate.
	/// <br> **Required**
	pub peer_hostname: String,

	/// UDP port where the QUIC server listens. In server mode, this determines the port to bind the socket at;
	/// in client mode, this determines the port to connect to.
	/// <br> **Default:** 20010
	#[serde(default = "default_quic_port")]
	pub quic_port: u16,

	/// Address to bind the QUIC socket at (valid in both server and client mode).
	/// <br> **Default:** `"::"` (IPv6 wildcard address)
	#[serde(default = "default_bind_address")]
	pub bind_address: IpAddr,

	/// Only valid in client mode: overrides the address to connect to the peer over QUIC.
	/// <br> **Default:** uses the value of `peer_hostname`
	pub connect_address: Option<String>,

	/// Only valid in client mode: socket address to bind the listening HTTP/1.1 endpoint at.
	/// <br> **Default:** `[::1]:20080`
	pub http_bind_address: Option<SocketAddr>,

	/// Only valid in server mode: socket address to send HTTP/1.1 requests (received from the peer) to.
	/// <br> **Required**
	pub http_connect_address: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMode {
	Client,
	Server,
}

fn default_quic_port() -> u16 {
	20010
}

fn default_bind_address() -> IpAddr {
	"::".parse().unwrap()
}

pub fn default_http_bind_address() -> SocketAddr {
	"[::1]:20080".parse().unwrap()
}

/// TLS identity settings for the QUIC endpoint.
#[derive(Deserialize, Debug)]
pub struct TlsConfig {
	/// Trusted root CA certificates to verify the certificate of the peer against.
	/// <br> **Default:** use system root CA store
	pub ca: Option<PathBuf>,

	/// Skip verification of the peer certificate. **Dangerous.**
	/// <br> **Default:** false
	#[serde(default)]
	pub skip_verify: bool,

	/// Path to certificate to present to peers.
	/// <br> **Required**
	pub cert: PathBuf,

	/// Path to certificate's private key.
	/// <br> **Required**
	pub key: PathBuf,
}

/// Configuration of the [transport configuration](`quinn::TransportConfig`) of the connection with the peer.
/// These parameters are usually kept identical on both sides.
#[derive(Deserialize, Debug, Default)]
pub struct TransportConfig {
	/// Maximum duration of inactivity to accept before considering the connection dead, in milliseconds.
	/// The true idle timeout is the minimum of this and the peer’s own max idle timeout.
	/// See [`quinn::TransportConfig::max_idle_timeout`].
	/// <br> **Default:** 5000
	pub max_idle_timeout: Option<u64>,

	/// Period of inactivity before sending a keep-alive packet, in milliseconds.
	/// Keep-alive packets prevent an inactive but otherwise healthy connection from timing out.
	/// See [`quinn::TransportConfig::keep_alive_interval`].
	/// <br> **Default:** 2000
	pub keep_alive_interval: Option<u64>,

	/// Initial estimate of RTT with the peer, in milliseconds.
	/// This is the value used before an RTT sample is taken.
	/// See [`quinn::TransportConfig::initial_rtt`].
	/// <br> **Default:** see quinn documentation (spec default)
	pub initial_rtt: Option<u64>,

	/// **Flow control:** Maximum number of HTTP streams (requests) that may be open concurrently at any point in time.
	/// [`quinn::TransportConfig::max_concurrent_bidi_streams`] is set to this value (for servers) or to zero (for clients).
	/// <br> **Default:** 100
	pub max_concurrent_http_streams: Option<u32>,

	/// **Flow control:** Maximum data the peer may transmit without acknowledgement on any one stream before becoming blocked, in bytes.
	/// See [`quinn::TransportConfig::stream_receive_window`].
	/// <br> **Default:** 1MB
	pub stream_receive_window: Option<u64>,

	/// **Congestion control:** Size of the initial congestion window, in bytes.
	/// See [`quinn::congestion::CubicConfig::initial_window`].
	/// <br> **Default:** 14720 (spec default)
	pub initial_window: Option<u64>,

	/// **Flow control:** Maximum data the peer may transmit across all streams of a connection before becoming blocked, in bytes.
	/// See [`quinn::TransportConfig::receive_window`].
	/// <br> **Default:** `initial_window`
	pub receive_window: Option<u64>,

	/// **Flow control:** Maximum data to transmit to a peer without acknowledgment, in bytes.
	/// See [`quinn::TransportConfig::send_window`].
	/// <br> **Default:** `initial_window`
	pub send_window: Option<u64>,

	/// **OS network:** Size of the OS's receive buffer for the UDP socket (`SO_RCVBUF` option), in bytes.
	/// See [`socket2::Socket::set_recv_buffer_size`].
	/// <br> **Default:** OS default
	pub socket_receive_buffer_size: Option<usize>,

	/// **OS network:** Size of the OS's send buffer for the UDP socket (`SO_SNDBUF` option), in bytes.
	/// See [`socket2::Socket::set_send_buffer_size`].
	/// <br> **Default:** OS default
	pub socket_send_buffer_size: Option<usize>,

	/// **Congestion control:** Algorithm to use for the congestion controller.
	/// <br> **Default:** Cubic
	#[serde(default)]
	pub congestion_algorithm: CongestionAlgorithm,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
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

pub fn default_max_idle_timeout() -> u64 {
	5000
}

pub fn default_keep_alive_interval() -> u64 {
	2000
}

pub fn default_max_concurrent_http_streams() -> u32 {
	100
}

pub fn default_stream_receive_window() -> u64 {
	1_000_000
}

/// Limits, timeouts, intervals and other parameters that affect operation of ptproxy. This includes
/// proxy behavior, integration with the service manager, and interaction with HTTP/1.1 upstreams / downstreams.
#[derive(Deserialize, Debug, Default)]
pub struct SystemConfig {
	/// Time to wait since last QUIC connection \[attempt\] failed before attempting a new connection, in milliseconds.
	/// Only used in client mode.
	/// <br> **Default:** 1000
	pub connect_interval: Option<u64>,
}

pub fn default_connect_interval() -> u64 {
	1000
}
