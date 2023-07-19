# ptproxy

## What's this?

It's an ad-hoc solution to proxy HTTP/1.1 requests over a sensitive network link.

A typical scenario of use is when you have a service (A) that needs to consume an HTTP API offered by another service (B), and those services are separated by a *sensitive network link* such as the public internet (e.g. they are in different datacenters). Rather than pointing A directly at B, you would start a ptproxy instance next to A in client mode, and a ptproxy instance next to B in server mode. Both ptproxy instances maintain a persistent session, and A issues HTTP requests to its ptproxy, which sends them over to B's ptproxy, which issues them at B.

## Why do I need this? What's a sensitive network link?

HTTP/1.1 has become the *lingua franca* for communication among microservices due to its simplicity and wide support. It usually works over inter-container or inter-datacenter links, but depending on the application it may be unsuitable to transport over some links (such as the public internet) for reasons such as:

 - **Substantial latency:** for applications that are latency-sensitive enough, the delay from additional RTTs introduced by TCP (such as in connection establishment, flow control and congestion control) may be prohibitive.

 - **Insecure:** links that cross untrusted boundaries, such as the public internet, may require requests to travel encrypted and authenticated against MITMs.

 - **Unstable:** the link may not have a known or guaranteed bandwidth, may be jittery or lossy, or may be subject to occasional or frequent congestion.

 - **Low bandwidth / transfer:** the link may be transfer-billed or have low bandwidth, benefitting from transport efficiency.

We say "sensitive network link" to refer to links that have at least some of these unwanted properties. Whether that's the case often depends on the particular application.

## What's wrong with a VPN?

An overlay network can get you a secure link over an insecure one, but it can't make the other problems (especially extra latency from establishment, congestion control) go away. A solution based around the request-response model is more appropriate here.

## What's wrong with HTTP[S]?

Nothing actually. TCP and TLS are in theory prepared to handle the above challenges (e.g. for latency there's TCP Fast Open and TLS 0-RTT), and there are some techniques that can be used to improve latency and stability (such as connection pooling, pre-establishment, HTTP/1.1 keepalive, pipelining). HTTP/2 allows multiplexing requests over a single connection (which improves congestion handling and removes the need for many earlier techniques) and compresses headers for efficiency. HTTP/3 drops TCP in favor of a better transport layer (QUIC) with a variety of improvements around handshake speed, size, head of line blocking and congestion control.

But having the final applications (i.e. the microservices) directly communicate this way is unfeasible, because:

 - Most do not implement many of the mentioned protocols / techniques (often including TLS), and rarely expose the necessary tweaks. This is often exacerbated by lack of language or OS support.

 - Even if they do, it's unpractical to configure the necessary tweaks directly at the application: the mechanism, knobs and units could vary in each case.

 - When more than one instance needs to access the link (i.e. load balancing or scaling) this can result in unnecessary connections, worsening response to congestion.

The solution to this is using a *reverse proxy* at each end of the link: this decouples application deployment from infrastructure, allows managing knobs from a central place, swapping services easily, etc. This is what ptproxy does.

## What's wrong with existing reverse proxies?

Most reverse proxies don't support the described usecase (a point-to-point link) very well. They usually act as a front server, accepting requests from final users and delivering them to upstreams over a private, controlled link. This design manifests in several ways:

 - The default congestion control is very conservative, which is okay for front servers but bad (sometimes even prohibitive) for point-to-point sessions. Since there's previous knowledge about the link, CC could be relaxed accordingly, but few proxies provide tweaks for this.

 - Support for HTTP/3 is also lacking in general, and even when the proxy supports it, it may not offer it as option for upstream requests (which is what we need here).

 - Configuration for this usecase is unintuitive and could have pitfalls (nginx for example does not validate upstream's certificate by default, supports compressing responses but not requests, doesn't enable TCP keepalive by default, needs clearing the `Connection` header for keepalive to be actually in place, needs a set of identically named directives on different modules to be added to both ends...).

 - The HTTP session isn't established until the first request(s) arrive, incurring additional latency for those. Also for nginx, the session isn't kept alive forever but for a default of 1h (it could be made to be infinite by touching several settings in both ends, but this isn't recommended because of the design of the server).

## What's this again?

ptproxy is a reverse proxy designed specifically for the use case of point-to-point links. It's meant to be portable, offer good control over the transport, easy to set up in both ends and relatively lightweight (though throughput isn't the priority). In the future it could support niche features such as reporting metrics of the established session, sessions against different servers, multiplexing different endpoints over the same session, ACLs...

Right now ptproxy only supports HTTP/3 as transport across instances. In addition to the transport improvements mentioned above, being userspace-based gives us better control over all tweaks independently of the OS. An important downside is that offload optimizations (both in kernel, hypervisors and routers) are much more developed around TCP than UDP.

ptproxy is written in Rust for:

 - **Portability:** HTTP/3 support is a mess in mainland Linux distros thanks to OpenSSL, and Rust avoids dependency on system libraries altogether. It also has much better crossplatform support.

 - **Control:** Rust's HTTP/3 ecosystem offers much more control, with most components allowing dependency injection, meaning internal knobs are less likely to be left unexposed. The stack is fully async and even compatible with custom event loops, should we need them in the future.
