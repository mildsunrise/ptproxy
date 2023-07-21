// FIXME: use async in closures, into_err

use std::{
	convert::identity as id,
	error::Error,
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
	path::PathBuf,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
	time::Duration,
};

use futures::future;
use rand::{seq::IteratorRandom, thread_rng};
use rustls::server::AllowAnyAuthenticatedClient;
use structopt::StructOpt;
use tokio::{io::AsyncWriteExt, net::lookup_host, time::sleep};
use tracing::{error, info};

use h3_quinn::quinn;

mod config;
mod utils;
use crate::config::PeerMode;

static ALPN: &[u8] = b"h3";

#[derive(StructOpt, Debug)]
#[structopt(name = "ptproxy")]
struct Opt {
	#[structopt(
		long,
		short,
		default_value = "/etc/ptproxy/config.toml",
		help = "Path to configuration file"
	)]
	pub config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
	tracing_subscriber::fmt()
		.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
		.with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
		.with_writer(std::io::stderr)
		.with_max_level(tracing::Level::INFO)
		.init();

	// parse args, read config

	let opt = Opt::from_args();
	let config: config::Config = toml::from_str(&tokio::fs::read_to_string(opt.config.clone()).await?)?;
	let config_base = opt.config.parent().unwrap();
	let general = config.general;
	let connect_interval = Duration::from_millis(
		config
			.transport
			.connect_interval
			.unwrap_or(config::default_connect_interval()),
	);

	// load TLS certificates / keys

	let roots = {
		let mut roots = rustls::RootCertStore::empty();
		let certs = match config.tls.ca {
			Some(path) =>
				crate::utils::load_certificates_from_pem(&config_base.join(path))?,
			None => rustls_native_certs::load_native_certs()?
				.into_iter()
				.map(|c| rustls::Certificate(c.0))
				.collect(),
		};
		for cert in certs {
			roots.add(&cert)?;
		}
		roots
	};

	let cert = crate::utils::load_certificates_from_pem(&config_base.join(config.tls.cert))?;
	let key = crate::utils::load_private_key_from_file(&config_base.join(config.tls.key))?;

	// prepare QUIC config

	let endpoint_config = quinn::EndpointConfig::default();

	let transport_config = Arc::new(crate::utils::build_transport_config(general.mode, &config.transport)?);

	let client_config = {
		let mut tls_config = rustls::ClientConfig::builder()
			.with_safe_default_cipher_suites()
			.with_safe_default_kx_groups()
			.with_protocol_versions(&[&rustls::version::TLS13])?
			.with_root_certificates(roots.clone())
			.with_client_auth_cert(cert.clone(), key.clone())?;
		tls_config.enable_early_data = true;
		tls_config.alpn_protocols = vec![ALPN.into()];
		tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

		let mut config = quinn::ClientConfig::new(Arc::new(tls_config));
		config.transport_config(transport_config.clone());
		config
	};

	let server_config = {
		let cert_verifier = Arc::new(crate::utils::StrictClientCertVerifier {
			inner: AllowAnyAuthenticatedClient::new(roots.clone()),
			server_name: general.hostname.as_str().try_into()?,
		});
		let mut tls_config = rustls::ServerConfig::builder()
			.with_safe_default_cipher_suites()
			.with_safe_default_kx_groups()
			.with_protocol_versions(&[&rustls::version::TLS13])?
			.with_client_cert_verifier(cert_verifier)
			.with_single_cert(cert.clone(), key.clone())?;
		tls_config.max_early_data_size = u32::MAX;
		tls_config.alpn_protocols = vec![ALPN.into()];
		tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

		let mut config = quinn::ServerConfig::with_crypto(Arc::new(tls_config));
		config.transport_config(transport_config.clone());
		config.migration(true);
		config.use_retry(false);
		config
	};

	// prepare addresses

	// (not resolved yet, we'll do that each connection attempt)
	let client_addr = (
		general
			.http_connect_address
			.clone()
			.unwrap_or(general.hostname.clone()),
		general.quic_port,
	);

	let endpoint_addr = SocketAddr::new(
		general.bind_address,
		match general.mode {
			PeerMode::Client => 0,
			PeerMode::Server => general.quic_port,
		},
	);

	if general.mode != PeerMode::Client && general.http_bind_address.is_some() {
		Err("http_bind_address can only be present in client mode")?
	}
	if general.mode != PeerMode::Server && general.http_connect_address.is_some() {
		Err("http_connect_address can only be present in server mode")?
	}
	if general.mode == PeerMode::Server && general.http_connect_address.is_none() {
		Err("http_connect_address must be present in server mode")?
	}

	let listener_addr = general
		.http_bind_address
		.clone()
		.unwrap_or(config::default_http_bind_address());

	// start QUIC endpoint

	let socket = std::net::UdpSocket::bind(endpoint_addr)?;
	crate::utils::configure_endpoint_socket(&socket, &config.transport)?;

	let endpoint = {
		let mut endpoint = quinn::Endpoint::new(
			endpoint_config,
			(general.mode == PeerMode::Server).then_some(server_config),
			socket,
			Arc::new(quinn::TokioRuntime),
		)?;
		if general.mode == PeerMode::Client {
			endpoint.set_default_client_config(client_config);
		}
		endpoint
	};

	// start listening for shutdown

	let stop_token = CancellationToken::new();
	{
		let stop_token = stop_token.clone();
		tokio::spawn(async move {
			tokio::signal::ctrl_c().await.unwrap();
			info!("stopping server...");
			stop_token.cancel();
		});
	}

	// main body

	// resolve destination
	let addr = lookup_host(client_addr)
		.await?
		.choose(&mut thread_rng())
		.ok_or("resolution found no addresses")?;

	// attempt to establish QUIC connection
	let quinn_connection = endpoint.connect(addr, &general.hostname)?.await?;

	// create HTTP/3 connection
	let h3_connection = h3_quinn::Connection::new(quinn_connection);
	let (mut driver, mut send_request) = h3::client::new(h3_connection).await?;

	let drive = async move {
		future::poll_fn(|cx| driver.poll_close(cx)).await?;
		Ok::<(), Box<dyn std::error::Error>>(())
	};

	// In the following block, we want to take ownership of `send_request`:
	// the connection will be closed only when all `SendRequest`s instances
	// are dropped.
	//
	//             So we "move" it.
	//                  vvvv
	let request = async move {
		info!("sending request ...");

		let req = http::Request::builder().uri(uri).body(())?;

		// sending request results in a bidirectional stream,
		// which is also used for receiving response
		let mut stream = send_request.send_request(req).await?;

		// finish on the sending side
		stream.finish().await?;

		info!("receiving response ...");

		let resp = stream.recv_response().await?;

		info!("response: {:?} {}", resp.version(), resp.status());
		info!("headers: {:#?}", resp.headers());

		// `recv_data()` must be called after `recv_response()` for
		// receiving potential response body
		while let Some(mut chunk) = stream.recv_data().await? {
			let mut out = tokio::io::stdout();
			out.write_all_buf(&mut chunk).await?;
			out.flush().await?;
		}

		Ok::<_, Box<dyn std::error::Error>>(())
	};

	let (req_res, drive_res) = tokio::join!(request, drive);
	req_res?;
	drive_res?;

	// wait for the connection to be closed before exiting
	client_endpoint.wait_idle().await;

	Ok(())
}
