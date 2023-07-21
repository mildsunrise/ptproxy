// FIXME: use async in closures, into_err

use std::{
	convert::{identity as id, Infallible},
	error::Error,
	net::SocketAddr,
	path::PathBuf,
	sync::{Arc, RwLock},
	time::Duration,
};

use bytes::Bytes;
use futures::stream::FuturesUnordered;
use h3::error::ErrorLevel;
use http::Response;
use hyper::{
	service::{make_service_fn, service_fn},
	Body, Server,
};
use rand::{seq::IteratorRandom, thread_rng};
use rustls::server::AllowAnyAuthenticatedClient;
use structopt::StructOpt;
use tokio::{io::AsyncWriteExt, net::lookup_host, select, time::sleep, try_join};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use h3_quinn::quinn;

mod config;
mod utils;
use crate::config::PeerMode;
use crate::utils::drain_stream;

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
	let config: config::Config =
		toml::from_str(&tokio::fs::read_to_string(opt.config.clone()).await?)?;
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
			Some(path) => crate::utils::load_certificates_from_pem(&config_base.join(path))?,
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

	let transport_config = Arc::new(crate::utils::build_transport_config(
		general.mode,
		&config.transport,
	)?);

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
			// a second ctrl_c exits immediately
			tokio::signal::ctrl_c().await.unwrap();
			std::process::exit(130);
		});
	}

	// main body: client

	struct EstablishedConnection {
		// this is inside an Option (even though EstablishedConnection itself can be or not be present)
		// because it's our way to signal h3 to send GOAWAY. but we may have other data in the
		// connection we might want to make accessible to the rest of the application even when
		// the connection is in the process of being closed.
		send_request: Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
	}

	struct ConnectionGuard<'a>(&'a RwLock<Option<EstablishedConnection>>);

	impl<'a> Drop for ConnectionGuard<'a> {
		fn drop(&mut self) {
			*self.0.write().unwrap() = None;
		}
	}

	let current_connection = Arc::new(RwLock::new(None::<EstablishedConnection>));

	let establish_client_connection = || async {
		// resolve destination
		let addr = lookup_host(&client_addr)
			.await?
			.choose(&mut thread_rng())
			.ok_or("resolution found no addresses")?;

		// attempt to establish QUIC connection
		let quinn_connection = endpoint.connect(addr, &general.hostname)?.await?;
		info!("connection {} established", quinn_connection.stable_id());

		// create HTTP/3 connection
		let h3_connection = h3_quinn::Connection::new(quinn_connection);
		let connection = h3::client::new(h3_connection).await?;

		Ok::<_, Box<dyn Error>>(connection)
	};

	let client_iteration = || async {
		// attempt to establish a connection (cancelling on shutdown)
		let (mut driver, send_request) = select! {
			() = stop_token.cancelled() => return Ok(()),
			value = establish_client_connection() => value,
		}?;

		// register new connection so incoming requests use it
		let state_guard = ConnectionGuard(&current_connection);
		*state_guard.0.write().unwrap() = Some(EstablishedConnection {
			send_request: Some(send_request),
		});
		info!("tunnel ready");

		// have we begun a connection close from our end? (equivalent to state_guard's send_request.is_some())
		let mut have_closed = false;

		// wait for connection end, while listening for a shutdown signal
		select! {
			true = async {
				stop_token.cancelled().await;
				if ! have_closed {
					have_closed = true;
					state_guard.0.write().unwrap().as_mut().unwrap().send_request = None;
				}
				false // won't match the branch pattern
			} => unreachable!(),
			value = driver.wait_idle() => value,
		}?;

		// if connection ended gracefully, check if it was due to us closing, or if it was the server
		// in the latter case, this is an error condition for us and we must report + reconnect if needed
		if !have_closed {
			Err("server closed the connection")?
		}

		// if it was due to us closing the connection, then it's because of shutdown, so signal this to the client loop
		Ok::<(), Box<dyn Error>>(())
	};

	let client_loop = || async {
		// client_iteration returns Ok(()) to signal shutdown
		while let Err(error) = client_iteration().await {
			error!("client connection failed: {}", error);
			sleep(connect_interval).await;
		}
		Ok::<(), Box<dyn Error>>(())
	};

	let handle_request_client = |request| {
		async move {
			Ok::<_, Infallible>(Response::<Body>::new("Hello, World".into()))
		}
	};

	let listener_loop = || async {
		let make_svc = make_service_fn(|_conn| async move {
			Ok::<_, Infallible>(service_fn(handle_request_client.clone()))
		});
		Server::bind(&listener_addr)
			.serve(make_svc)
			.with_graceful_shutdown(stop_token.cancelled())
			.await?;
		Ok::<(), Box<dyn Error>>(())
	};

	// main body: server

	let handle_request_server = |(req, stream)| async move {
		info!("new request: {:#?}", req);
		// TODO
		Ok::<_, Box<dyn Error + Sync + Send>>(())
	};

	let handle_established_connection_server = |quinn_connection: quinn::Connection| {
		let stop_token = &stop_token;
		async move {
			// create HTTP/3 connection
			let h3_connection = h3_quinn::Connection::new(quinn_connection.clone());
			let mut connection = select! {
				() = stop_token.cancelled() => return Ok(()),
				value = h3::server::Connection::<_, Bytes>::new(h3_connection) => value,
			}?;

			// accept requests while not shutdown
			let result = loop {
				let request = select! {
					() = stop_token.cancelled() => break Ok(()),
					value = connection.accept() => value,
				};

				// handle accept() errors
				let request = match request {
					Ok(Some(value)) => value,
					// no more streams to be received
					Ok(None) => break Err("client closed the connection".into()),
					Err(err) => {
						if err.get_error_level() == ErrorLevel::StreamError {
							error!(
								"connection {} failed accepting: {}",
								quinn_connection.stable_id(),
								err
							);
							continue;
						}
						break Err(err.into());
					}
				};

				// spawn a task to handle the request
				tokio::spawn(handle_request_server(request));
			};

			// wait for outstanding requests to be processed
			// (here we .and() to result because if both accept and
			// shutdown fail, the likely correct thing to do is report the 1st error)
			let result = result.and(connection.shutdown(100).await.map_err(|err| err.into())); // FIXME: make configurable

			id::<Result<_, Box<dyn Error>>>(result)
		}
	};

	let handle_connection_server = |connection| async {
		// carry the connection handshake, unless shutdown
		let connection = select! {
			() = stop_token.cancelled() => return,
			value = connection => value,
		};
		let connection: quinn::Connection = match connection {
			Ok(value) => value,
			// don't report on connection errors until we can trust the other peer;
			// if legitimate, the errors will appear on the client anyway
			Err(_) => return,
		};
		info!("connection {} established", connection.stable_id());

		// process the established connection
		let result = handle_established_connection_server(connection.clone()).await;

		// if Ok(()) then shutdown, otherwise report connection error
		if let Err(error) = result {
			error!("connection {} failed: {}", connection.stable_id(), error);
		}
	};

	let server_loop = || async {
		let mut connections = FuturesUnordered::new();

		loop {
			// wait for a connection attempt to arrive, unless shutdown
			// (in the meantime drive the existing connections, if any)
			let connecting: quinn::Connecting = select! {
				() = stop_token.cancelled() => break,
				value = endpoint.accept() => value,
				true = async {
					drain_stream(&mut connections).await;
					false // won't match the branch pattern
				} => unreachable!(),
			}.unwrap();

			// use spawn_local (i.e. run the handlers in our same thread) because ptproxy
			// is meant to be a point-to-point proxy and so there will usually be a
			// single connection to handle, save for exceptional states. thus it's not
			// worth it to subject ourselves to the restrictions of spawn() just so
			// they can run in other threads.
			connections.push(handle_connection_server(connecting));
		}

		// wait for outstanding connections to be closed
		drain_stream(&mut connections).await;
	};

	// run the thing!

	match general.mode {
		PeerMode::Client => {
			// start HTTP/1.1 server + connection establishing loop
			try_join!(listener_loop(), client_loop())?;
		}
		PeerMode::Server => {
			// start HTTP/3 server
			server_loop().await;
		}
	}

	// close any remaining QUIC connection in the endpoint (should never happen, but just in case)
	endpoint.close(
		h3::error::Code::H3_NO_ERROR.value().try_into().unwrap(),
		&[],
	);

	// wait for the (closed) connections to completely extinguish
	info!("waiting for endpoint to finish...");
	endpoint.wait_idle().await;

	Ok(())
}
