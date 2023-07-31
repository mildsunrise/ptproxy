#![feature(try_blocks, byte_slice_trim_ascii)]
// FIXME: use async in closures, into_err

use std::{
	convert::{identity as id, Infallible},
	error::Error,
	net::SocketAddr,
	path::PathBuf,
	sync::{Arc, Mutex, atomic::AtomicBool},
	time::Duration,
};
use std::sync::atomic::Ordering::SeqCst;

use bytes::{Bytes, Buf};
use futures::stream::FuturesUnordered;
use h3::error::{ErrorLevel, Code};
use http::{Response, Request, HeaderName, header, HeaderMap, HeaderValue, Method, StatusCode, uri::Scheme, Uri};
use hyper::{
	service::{make_service_fn, service_fn},
	Body, Server, body::HttpBody,
};
use rand::{seq::IteratorRandom, thread_rng};
use rustls::server::AllowAnyAuthenticatedClient;
use sd_notify::{notify, NotifyState};
use structopt::StructOpt;
use tokio::{net::lookup_host, select, time::sleep, try_join};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use h3_quinn::quinn;

mod config;
mod utils;
use crate::config::PeerMode;
use crate::utils::{cancellable, drain_stream, with_background};

static ALPN: &[u8] = b"h3";

#[derive(StructOpt, Debug)]
#[structopt(about)]
struct Opt {
	#[structopt(
		long,
		short,
		default_value = "/etc/ptproxy/config.toml",
		help = "Path to configuration file"
	)]
	pub config: PathBuf,
}

// we override the real main to catch application errors and report as systemd status too
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
	let result = real_main().await;
	if let Err(ref err) = result {
		let msg = format!("failed: {}", err);
		let _ = notify(false, &[NotifyState::Status(&msg)]);
	}
	result
}

async fn real_main() -> Result<(), Box<dyn Error>> {
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
			.system
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
			server_name: general.peer_hostname.as_str().try_into()?,
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
			.connect_address
			.clone()
			.unwrap_or(general.peer_hostname.clone()),
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

	// prepare the base upstream URL now, this way we also validate the address is valid
	let upstream_url = match general.http_connect_address {
		None => None,
		Some(addr) => Some(Uri::builder()
			.scheme(Scheme::HTTP)
			.authority(addr)
			.path_and_query("/") // dummy path so it accepts it
			.build()?),
	};

	let tcp_nodelay = config
		.system
		.tcp_nodelay
		.unwrap_or(config::default_tcp_nodelay());

	let mut http_connector = hyper::client::connect::HttpConnector::new();
	// FIXME: make configurable
	http_connector.set_keepalive(Some(Duration::from_millis(15000)));
	http_connector.set_nodelay(tcp_nodelay);

	let http_client = hyper::Client::builder()
		.http1_title_case_headers(true)
		.set_host(false)
		.build(http_connector);

	let http_server = match general.mode {
		PeerMode::Server => None,
		PeerMode::Client => Some(Server::try_bind(&listener_addr)?
			.tcp_nodelay(tcp_nodelay)
			.http1_title_case_headers(true))
	};

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

	// start listening for shutdown and sending watchdog

	let ready_sent = Arc::new(AtomicBool::new(false));

	let send_status = move |message: &str, is_ready: bool| {
		let states = [
			NotifyState::Status(message),
			NotifyState::Ready,
		];
		let add_ready = is_ready && !ready_sent.swap(true, SeqCst);
		let states = &states[0..(1 + add_ready as usize)];
		let _ = notify(false, &states);
	};

	let stop_token = CancellationToken::new();
	{
		let stop_token = stop_token.clone();
		let send_status = send_status.clone();
		tokio::spawn(async move {
			tokio::signal::ctrl_c().await.unwrap();
			info!("stopping server...");
			send_status("stopping server", false);
			stop_token.cancel();
			let _ = notify(false, &[NotifyState::Stopping]);

			// a second ctrl_c exits immediately
			tokio::signal::ctrl_c().await.unwrap();
			std::process::exit(130);
		});
	}

	let watchdog_interval = {
		let watchdog_factor = config.system.watchdog_factor.unwrap_or(config::default_watchdog_factor());
		let watchdog_usec = {
			let mut result = 0;
			sd_notify::watchdog_enabled(true, &mut result).then_some(result)
		};
		watchdog_usec.map(|x| Duration::from_secs_f32((x as f32) / (watchdog_factor * 1e6)))
	};

	let watchdog_loop = async {
		// FIXME: this runs in the main tokio task, but it should in turn get pings
		// from the tasks spawned to handle requests in case a deadlock occurs there
		if let Some(watchdog_interval) = watchdog_interval {
			loop {
				let _ = notify(false, &[NotifyState::Watchdog]);
				sleep(watchdog_interval).await;
			}
		}
	};

	let wait_for_first_attempt = config
		.system
		.wait_for_first_attempt
		.unwrap_or(config::default_wait_for_first_attempt());

	// main body: client

	struct EstablishedConnection {
		// this is inside an Option (even though EstablishedConnection itself can be or not be present)
		// because it's our way to signal h3 to send GOAWAY. but we may have other data in the
		// connection we might want to make accessible to the rest of the application even when
		// the connection is in the process of being closed.
		send_request: Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
	}

	struct ConnectionGuard<'a>(&'a Mutex<Option<EstablishedConnection>>);

	impl<'a> Drop for ConnectionGuard<'a> {
		fn drop(&mut self) {
			*self.0.lock().unwrap() = None;
		}
	}

	let current_connection = Arc::new(Mutex::new(None::<EstablishedConnection>));

	let establish_client_connection = || async {
		// resolve destination
		let addr = lookup_host(&client_addr)
			.await?
			.choose(&mut thread_rng())
			.ok_or("resolution found no addresses")?;

		// attempt to establish QUIC connection
		let quinn_connection = endpoint.connect(addr, &general.peer_hostname)?.await?;
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
		*state_guard.0.lock().unwrap() = Some(EstablishedConnection {
			send_request: Some(send_request),
		});
		info!("tunnel established");
		send_status("tunnel established", true);

		// have we begun a connection close from our end? (equivalent to state_guard's send_request.is_some())
		let mut have_closed = false;

		// wait for connection end, while listening for a shutdown signal
		with_background(driver.wait_idle(), async {
			stop_token.cancelled().await;
			if !have_closed {
				have_closed = true;
				state_guard.0.lock().unwrap().as_mut().unwrap().send_request = None;
			}
		})
		.await?;

		// if connection ended gracefully, check if it was due to us closing, or if it was the server
		// in the latter case, this is an error condition for us and we must report + reconnect if needed
		if !have_closed {
			Err("server closed the connection")?
		}

		// if it was due to us closing the connection, then it's because of shutdown, so signal this to the client loop
		Ok::<(), Box<dyn Error>>(())
	};

	let client_loop = || async {
		send_status("attempting first connection", !wait_for_first_attempt);

		// client_iteration returns Ok(()) to signal shutdown
		while let Err(error) = client_iteration().await {
			error!("client connection failed: {}", error);
			send_status(&format!("client connection failed: {}", error), true);
			sleep(connect_interval).await;
		}
		Ok::<(), Box<dyn Error>>(())
	};

	let handle_request_client = {
		let current_connection = current_connection.clone();
		move |mut request: Request<Body>| {
			let current_connection = current_connection.clone();
			async move {
				// reject CONNECT requests
				if request.method() == Method::CONNECT {
					return Ok(Response::builder()
						.header(header::SERVER, "ptproxy client")
						.status(StatusCode::METHOD_NOT_ALLOWED)
						.body("CONNECT requests not implemented yet\n".into())
						.unwrap());
				}

				// TODO: enforce Host to be present, enforce URL to have only a path

				// handle Transfer-Encoding
				let chunked = match is_chunked_message(request.headers()) {
					Some(x) => x,
					None => return Ok(Response::builder()
						.header(header::SERVER, "ptproxy client")
						.status(StatusCode::BAD_REQUEST)
						.body("invalid Transfer-Encoding value: only chunked transfer coding supported\n".into())
						.unwrap()),
				};
				if chunked {
					request.headers_mut().remove(header::CONTENT_LENGTH);
				}

				// do this as the last step, since previous steps depend on reading connection headers
				remove_hop_by_hop_headers(request.headers_mut());

				// retrieve current tunnel to send requests over
				let send_request = {
					let current_connection = current_connection.lock().unwrap();
					current_connection.as_ref().and_then(|s| s.send_request.clone())
				};
				let mut send_request = match send_request {
					Some(value) => value,
					None => return Ok(Response::builder()
						.header(header::SERVER, "ptproxy client")
						.status(StatusCode::SERVICE_UNAVAILABLE)
						.body("tunnel not established\n".into())
						.unwrap()),
				};

				// actually (attempt to) proxy the request
				*request.version_mut() = http::Version::HTTP_3;
				let (mut body, request) = {
					let (parts, body) = request.into_parts();
					(body, Request::from_parts(parts, ()))
				};
				//info!("forwarded request: {:#?}", request);
				let mut stream = match send_request.send_request(request).await {
					Ok(value) => value,
					Err(err) => return Ok(Response::builder()
						.header(header::SERVER, "ptproxy client")
						.status(StatusCode::BAD_GATEWAY)
						.body(format!("error sending request:\n{}\n", err).into())
						.unwrap()),
				};

				// proxy request body
				let proxy_request_body = async {
					while let Some(buf) = body.data().await {
						let buf = buf.map_err(|err| format!("when receiving data: {}", err))?;
						stream.send_data(buf).await.map_err(|err| format!("when sending data: {}", err))?;
					}
					stream.finish().await.map_err(|err| format!("when finishing stream: {}", err))?;
					Ok::<_, Box<dyn Error>>(())
				};
				if let Err(err) = proxy_request_body.await {
					return Ok(Response::builder()
						.header(header::SERVER, "ptproxy client")
						.status(StatusCode::BAD_GATEWAY)
						.body(format!("error when streaming request body:\n{}\n", err).into())
						.unwrap())
				}

				// proxy response
				let mut response = match stream.recv_response().await {
					Ok(value) => value,
					Err(err) => return Ok(Response::builder()
						.header(header::SERVER, "ptproxy client")
						.status(StatusCode::BAD_GATEWAY)
						.body(format!("error when receiving response:\n{}\n", err).into())
						.unwrap())
				};
				//info!("response: {:#?}", response);

				// FIXME: do we need to add transfer-encoding ourselves?

				// actually (attempt to) proxy the response
				*response.version_mut() = http::Version::HTTP_11;
				let (mut sender, response) = {
					let (sender, body) = Body::channel();
					(sender, Response::from_parts(response.into_parts().0, body))
				};
				tokio::spawn(async move {
					let result: Result<(), Box<dyn Error + Send + Sync>> = try {
						while let Some(mut buf) = {
							stream.recv_data().await.map_err(|err| format!("when receiving data: {}", err))?
						} {
							// FIXME: if server closes the connection, don't raise error, instead stream.stop_sending() and return.
							// in case the server is closing the connection because it has issued an early response, then
							// response will resolve and if not, then response future will fail anyway
							sender.send_data(buf.copy_to_bytes(buf.remaining())).await.map_err(|err| format!("when sending data: {}", err))?;
						}
					};
					if let Err(err) = result {
						// this call already causes the async block to take ownership of 'sender',
						// meaning it will be dropped also after a successful stream
						sender.abort();
						error!("error when proxying response: {}", err);
					}
				});
				Ok::<_, Infallible>(response)
			}
		}
	};

	let listener_loop = || async {
		let make_svc = make_service_fn(move |_conn| {
			let handle_request_client = handle_request_client.clone();
			async move {
				Ok::<_, Infallible>(service_fn(handle_request_client))
			}
		});
		http_server
			.unwrap()
			.serve(make_svc)
			.with_graceful_shutdown(stop_token.cancelled())
			.await?;
		Ok::<(), Box<dyn Error>>(())
	};

	// main body: server

	let handle_request_server = |(mut request, mut stream): (Request<()>, h3::server::RequestStream<_, _>)| {
		let upstream_url = upstream_url.clone().unwrap();
		let http_client = http_client.clone();
		async move {
			//info!("request: {:#?}", request);

			// deconvert url + host header
			if request.uri().scheme() != Some(&Scheme::HTTPS) {
				// FIXME: send 400
			}
			if !request.headers().contains_key(header::HOST) {
				let authority = match request.uri().authority() {
					Some(value) => value,
					None => unreachable!(), //FIXME: send 400
				};
				let value = authority.as_str().try_into().unwrap();
				request.headers_mut().append(header::HOST, value);
			}
			*request.uri_mut() = {
				let mut parts = upstream_url.into_parts();
				parts.path_and_query = Some(request.uri().path_and_query().unwrap().clone());
				Uri::from_parts(parts).unwrap()
			};

			// FIXME: do we need to add transfer-encoding ourselves?

			// actually (attempt to) proxy the request
			*request.version_mut() = http::Version::HTTP_11;
			let (mut sender, request) = {
				let (sender, body) = Body::channel();
				(sender, Request::from_parts(request.into_parts().0, body))
			};
			let response: Result<_, Box<dyn Error + Sync + Send>> = try_join!(
				async {
					Ok(http_client.request(request).await.map_err(|err| format!("when making request: {}", err))?)
				},
				async {
					let result = try {
						while let Some(mut buf) = {
							stream.recv_data().await.map_err(|err| format!("when receiving data: {}", err))?
						} {
							// FIXME: if server closes the connection, don't raise error, instead stream.stop_sending() and return.
							// in case the server is closing the connection because it has issued an early response, then
							// response will resolve and if not, then response future will fail anyway
							sender.send_data(buf.copy_to_bytes(buf.remaining())).await.map_err(|err| format!("when sending data: {}", err))?;
						}
					};
					if let Err(_) = result {
						// this call already causes the async block to take ownership of 'sender',
						// meaning it will be dropped also after a successful stream
						sender.abort();
					}
					result
				}
			);
			let mut response = match response {
				Ok((value, ())) => value,
				Err(err) => {
					// FIXME: maybe handle errors when sending this response in a better way?
					let body: Bytes = format!("could not proxy request:\n{}\n", err).into();
					stream.send_response(Response::builder()
						.header(header::SERVER, "ptproxy server")
						.header(header::CONTENT_LENGTH, body.len())
						.status(StatusCode::BAD_GATEWAY)
						.body(())
						.unwrap()).await?;
					stream.send_data(body).await?;
					stream.stop_sending(Code::H3_NO_ERROR);
					stream.finish().await?;
					return Ok(());
				},
			};

			// handle Transfer-Encoding
			let chunked = match is_chunked_message(response.headers()) {
				Some(x) => x,
				None => unreachable!(), // FIXME: send 502
			};
			if chunked {
				response.headers_mut().remove(header::CONTENT_LENGTH);
			}

			// do this as the last step, since previous steps depend on reading connection headers
			remove_hop_by_hop_headers(response.headers_mut());

			// proxy response
			*response.version_mut() = http::Version::HTTP_3;
			let (mut body, response) = {
				let (parts, body) = response.into_parts();
				(body, Response::from_parts(parts, ()))
			};
			//info!("forwarded response: {:#?}", response);
			if let Err(err) = stream.send_response(response).await {
				error!("error sending response: {}", err);
				stream.stop_stream(Code::H3_INTERNAL_ERROR);
				return Ok(());
			}
			let proxy_response_body = async {
				while let Some(buf) = body.data().await {
					let buf = buf.map_err(|err| format!("when receiving data: {}", err))?;
					stream.send_data(buf).await.map_err(|err| format!("when sending data: {}", err))?;
				}
				stream.finish().await.map_err(|err| format!("when finishing stream: {}", err))?;
				Ok::<_, Box<dyn Error>>(())
			};
			if let Err(err) = proxy_response_body.await {
				error!("error sending response body: {}", err);
				stream.stop_stream(Code::H3_INTERNAL_ERROR);
				return Ok(());
			}
			Ok::<_, Box<dyn Error + Sync + Send>>(())
		}
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
		info!("connection {} established ({})", connection.stable_id(), connection.remote_address());

		// process the established connection
		let result = handle_established_connection_server(connection.clone()).await;

		// if Ok(()) then shutdown, otherwise report connection error
		if let Err(error) = result {
			error!("connection {} failed: {}", connection.stable_id(), error);
		}
	};

	let server_loop = || async {
		let mut connections = FuturesUnordered::new();
		send_status("accepting connections", true);

		loop {
			// wait for a connection attempt to arrive, unless shutdown
			// (in the meantime drive the existing connections, if any)
			let accept_future = with_background(
				cancellable(endpoint.accept(), &stop_token),
				drain_stream(&mut connections),
			);
			let connecting = match accept_future.await {
				None => break, // shutdown: stop accepting connections
				Some(new_conn) => new_conn.unwrap(),
			};

			// use FuturesUnordered (i.e. run the handlers in our same thread) because
			// ptproxy is meant to be a point-to-point proxy and so there will usually
			// be a single connection to handle, save for exceptional states. thus it's
			// not worth it to subject ourselves to the restrictions of spawn() just so
			// they can run in other threads.
			connections.push(handle_connection_server(connecting));
		}

		// wait for outstanding connections to be closed
		send_status("waiting for outstanding connections to close", false);
		drain_stream(&mut connections).await;
	};

	// run the thing!

	let main_loop = async {
		info!("started endpoint at {}", endpoint.local_addr()?);

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
		endpoint.close(Code::H3_NO_ERROR.value().try_into().unwrap(), &[]);

		// wait for the (closed) connections to completely extinguish
		info!("waiting for endpoint to finish...");
		send_status("waiting for endpoint to finish", false);
		endpoint.wait_idle().await;

		Ok(())
	};

	with_background(main_loop, watchdog_loop).await
}

// header manipulation

static HEADER_KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
static HEADER_PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");

fn split_comma(value: &HeaderValue) -> impl Iterator<Item = &[u8]> {
	value.as_bytes().split(|b| *b == b',').map(|t| t.trim_ascii())
}

/// split a simple header (one that does not admit a comma in its value) into its individual values
fn split_simple_header(headers: &HeaderMap<HeaderValue>, header: HeaderName) -> impl Iterator<Item = &[u8]> {
	headers.get_all(header).iter().map(split_comma).flatten()
}

fn remove_hop_by_hop_headers(headers: &mut HeaderMap<HeaderValue>) {
	static KNOWN_HOP_BY_HOP_HEADERS: &[&HeaderName] = &[
		&header::CONNECTION,
		&header::TE,
		&header::TRANSFER_ENCODING,
		&header::TRAILER,
		&HEADER_KEEP_ALIVE,
		&header::UPGRADE,
		&HEADER_PROXY_CONNECTION,
		&header::PROXY_AUTHENTICATE,
		&header::PROXY_AUTHORIZATION,
	];

	// remove hop-by-hop headers listed in the connection header
	let connection_headers: Vec<HeaderName> = split_simple_header(headers, header::CONNECTION)
		.filter_map(|value| HeaderName::from_bytes(value).ok())
		.filter(|value| value != "close")
		.collect();
	for name in connection_headers {
		headers.remove(name);
	}

	// finally, remove any known hop-by-hop headers just in case
	for name in KNOWN_HOP_BY_HOP_HEADERS {
		headers.remove(*name);
	}
}

fn is_chunked_message(headers: &HeaderMap<HeaderValue>) -> Option<bool> {
	let value: Vec<_> = headers.get_all(header::TRANSFER_ENCODING).iter().collect();
	if value.is_empty() {
		return Some(false)
	}

	// if Transfer-Encoding is present, then it must specify 'chunked' as a single coding.
	if value.len() != 1 {
		return None
	}
	let value = value.get(0).unwrap().as_bytes().to_ascii_lowercase();
	// chunked doesn't have encoding parameters, so this is all we need:
	if value != b"chunked" {
		return None
	}

	Some(true)
}
