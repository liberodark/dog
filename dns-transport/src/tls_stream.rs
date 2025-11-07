use super::Error;
use super::HttpsTransport;
use super::TlsTransport;
use std::net::TcpStream;

#[cfg(any(feature = "with_nativetls", feature = "with_nativetls_vendored"))]
fn stream_nativetls(domain: &str, port: u16) -> Result<native_tls::TlsStream<TcpStream>, Error> {
    let connector = native_tls::TlsConnector::new()?;
    let stream = TcpStream::connect((domain, port))?;
    Ok(connector.connect(domain, stream)?)
}

#[cfg(feature = "with_rustls")]
fn stream_rustls(
    domain: &str,
    port: u16,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, Error> {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;

    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name =
        ServerName::try_from(domain.to_owned()).map_err(|_| Error::RustlsInvalidDnsNameError)?;

    let conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;

    let sock = TcpStream::connect((domain, port))?;
    let tls = rustls::StreamOwned::new(conn, sock);

    Ok(tls)
}

pub trait TlsStream<S: std::io::Read + std::io::Write> {
    fn stream(domain: &str, port: u16) -> Result<S, Error>;
}

#[cfg(any(feature = "with_tls", feature = "with_https"))]
cfg_if::cfg_if! {
    if #[cfg(any(feature = "with_nativetls", feature = "with_nativetls_vendored"))] {

        impl TlsStream<native_tls::TlsStream<TcpStream>> for HttpsTransport {
            fn stream(domain: &str, port: u16) -> Result<native_tls::TlsStream<TcpStream>, Error> {
                stream_nativetls(domain, port)
            }
        }

        impl TlsStream<native_tls::TlsStream<TcpStream>> for TlsTransport {
            fn stream(domain: &str, port: u16) -> Result<native_tls::TlsStream<TcpStream>, Error> {
                stream_nativetls(domain, port)
            }
        }

    } else if #[cfg(feature = "with_rustls")] {

        impl TlsStream<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> for HttpsTransport {
            fn stream(domain: &str, port: u16) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, Error> {
                stream_rustls(domain, port)
            }
        }

        impl TlsStream<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> for TlsTransport {
            fn stream(domain: &str, port: u16) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, Error> {
                stream_rustls(domain, port)
            }
        }

    } else {
        unreachable!("tls/https enabled but no tls implementation provided");
    }
}
