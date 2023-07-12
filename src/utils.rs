use std::{sync::Arc, time::Duration, path::Path};

use crate::config;

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
pub fn load_private_key_from_file(path: &Path) -> Result<rustls::PrivateKey, Box<dyn std::error::Error>> {
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
	original: &config::TransportConfig,
) -> Result<quinn::TransportConfig, Box<dyn std::error::Error>> {
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

	let mut derived = quinn::TransportConfig::default();
	derived.keep_alive_interval(Some(keep_alive_interval));
	derived.max_idle_timeout(Some(quinn::IdleTimeout::try_from(max_idle_timeout)?));
	set_congestion_controller(&mut derived, &original);
	if let Some(initial_rtt) = original.initial_rtt {
		derived.initial_rtt(Duration::from_millis(initial_rtt));
	};

	Ok(derived)
}

fn set_congestion_controller(
	target: &mut quinn::TransportConfig,
	config: &config::TransportConfig,
) {
	let initial_window = config.initial_window.unwrap_or(14720);
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
