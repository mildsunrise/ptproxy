use std::{sync::Arc, time::Duration, path::Path, error::Error, pin::Pin, future::Future};

use futures::{future::poll_fn, Stream};
use tokio_util::sync::CancellationToken;

use crate::config;

// async utils

/// a future that polls an Unpin stream, discarding all items, until it terminates.
pub async fn drain_stream<S: Stream + Unpin>(stream: &mut S) {
	while let Some(_) = poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await {};
}

/// a future that resolves when 'a' does, but also drives 'b' in the meantime.
/// in case 'b' ends first, its result is discarded and it keeps polling 'a' only.
pub async fn with_background<A: Future, B: Future>(a: A, b: B) -> A::Output {
	tokio::select! {
		x = a => x,
		true = async {
			b.await;
			false // prevent branch from matching
		} => unreachable!(),
	}
}

/// a future that resolves with Some(_) if 'a' resolves,
/// and resolves with None if the CancellationToken is cancelled first.
pub async fn cancellable<F: Future>(a: F, token: &CancellationToken) -> Option<F::Output> {
	tokio::select! {
		x = a => Some(x),
		() = token.cancelled() => None,
	}
}

// TLS stuff

pub struct StrictClientCertVerifier {
	pub server_name: rustls::ServerName,
	pub inner: rustls::server::AllowAnyAuthenticatedClient,
}

impl rustls::server::ClientCertVerifier for StrictClientCertVerifier {
	fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
		&[]
	}

	fn verify_client_cert(
		&self,
		end_entity: &rustls::Certificate,
		intermediates: &[rustls::Certificate],
		now: std::time::SystemTime,
	) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
		let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
		rustls::client::verify_server_name(&cert, &self.server_name)?;
		self.inner
			.verify_client_cert(end_entity, intermediates, now)
	}
}

// copied from rustls::Certificate
pub fn load_certificates_from_pem(path: &Path) -> std::io::Result<Vec<rustls::Certificate>> {
	let file = std::fs::File::open(path)?;
	let mut reader = std::io::BufReader::new(file);
	let certs = rustls_pemfile::certs(&mut reader)?;
	Ok(certs.into_iter().map(rustls::Certificate).collect())
}

// copied from rustls::PrivateKey
pub fn load_private_key_from_file(path: &Path) -> Result<rustls::PrivateKey, Box<dyn Error>> {
	let file = std::fs::File::open(path)?;
	let mut reader = std::io::BufReader::new(file);
	let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;

	match keys.len() {
		0 => Err("No PKCS8-encoded private key found".into()),
		1 => Ok(rustls::PrivateKey(keys.remove(0))),
		_ => Err("More than one PKCS8-encoded private key found".into()),
	}
}

// Conversion of our config into quinn

pub fn build_transport_config(
	mode: config::PeerMode,
	original: &config::TransportConfig,
) -> Result<quinn::TransportConfig, Box<dyn Error>> {
	let keep_alive_interval = Duration::from_millis(
		original
			.keep_alive_interval
			.unwrap_or(config::default_keep_alive_interval()),
	);
	let max_idle_timeout = Duration::from_millis(
		original
			.max_idle_timeout
			.unwrap_or(config::default_max_idle_timeout()),
	);
	let max_concurrent_bidi_streams = match mode {
		config::PeerMode::Client => 0, // HTTP/3 clients don't allow incoming bidi streams
		config::PeerMode::Server => original
			.max_concurrent_http_streams
			.unwrap_or(config::default_max_concurrent_http_streams()),
	};
	let stream_receive_window = original
		.stream_receive_window
		.unwrap_or(config::default_stream_receive_window());
	let initial_window = get_initial_window(original);
	let receive_window = original.receive_window.unwrap_or(initial_window);
	let send_window = original.send_window.unwrap_or(initial_window);

	let mut derived = quinn::TransportConfig::default();
	derived.keep_alive_interval(Some(keep_alive_interval));
	derived.max_idle_timeout(Some(quinn::IdleTimeout::try_from(max_idle_timeout)?));
	derived.receive_window(receive_window.try_into()?);
	derived.send_window(send_window);
	derived.datagram_receive_buffer_size(None); // HTTP/3 doesn't need datagrams
	derived.max_concurrent_bidi_streams(max_concurrent_bidi_streams.into());
	derived.stream_receive_window(stream_receive_window.try_into()?);
	set_congestion_controller(&mut derived, &original);
	if let Some(initial_rtt) = original.initial_rtt {
		derived.initial_rtt(Duration::from_millis(initial_rtt));
	};

	Ok(derived)
}

fn get_initial_window(config: &config::TransportConfig) -> u64 {
	config.initial_window.unwrap_or(14720)
}

fn set_congestion_controller(
	target: &mut quinn::TransportConfig,
	config: &config::TransportConfig,
) {
	let initial_window = get_initial_window(config);
	match config.congestion_algorithm {
		config::CongestionAlgorithm::Bbr => target.congestion_controller_factory(Arc::new(
			quinn::congestion::BbrConfig::default().initial_window(initial_window).clone(),
		)),
		config::CongestionAlgorithm::Cubic => target.congestion_controller_factory(Arc::new(
			quinn::congestion::CubicConfig::default().initial_window(initial_window).clone(),
		)),
		config::CongestionAlgorithm::NewReno => target.congestion_controller_factory(Arc::new(
			quinn::congestion::NewRenoConfig::default().initial_window(initial_window).clone(),
		)),
	};
}

pub fn configure_endpoint_socket(
	std_socket: &std::net::UdpSocket,
	config: &config::TransportConfig,
) -> Result<(), Box<dyn Error>> {
	let socket = socket2::SockRef::from(&std_socket);
	if let Some(value) = config.socket_receive_buffer_size {
		socket.set_recv_buffer_size(value)?;
	}
	if let Some(value) = config.socket_send_buffer_size {
		socket.set_send_buffer_size(value)?;
	}
	Ok(())
}
