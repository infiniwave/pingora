// Copyright 2025 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::protocols::tls::TlsStream;
use crate::protocols::IO;

use log::debug;
use pingora_error::ErrorType::{InternalError, TLSHandshakeFailure};
use pingora_error::{Error, OrErr, Result};
use pingora_rustls::{
    crypto_provider, load_certs_and_key_files, CertifiedKey, ClientHello, LazyConfigAcceptor,
    RusTlsServerAcceptor, ServerConfig, StartHandshake,
};
use pingora_rustls::{version, ResolvesServerCert, ResolvesServerCertUsingSni};

/// A boxed future that resolves to an `Arc<ServerConfig>`.
pub type AsyncServerConfigFuture =
    Pin<Box<dyn Future<Output = Result<Arc<ServerConfig>>> + Send + 'static>>;
/// A callback type that takes client hello information and returns a future
/// that resolves to a server configuration.
///
/// This allows asynchronous certificate fetching based on the client hello,
/// enabling dynamic certificate selection based on SNI, ALPN, or other
/// client hello fields.
pub type AsyncCertCallback =
    Arc<dyn Fn(ClientHelloInfo) -> AsyncServerConfigFuture + Send + Sync + 'static>;

/// Information extracted from the TLS ClientHello message.
///
/// This struct provides access to relevant fields from the client hello
/// that can be used to make certificate selection decisions.
#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    pub sni: Option<String>,
    pub alpn: Vec<Vec<u8>>,
    pub signature_schemes: Vec<u16>,
    pub cipher_suites: Vec<u16>,
}

impl ClientHelloInfo {
    pub fn from_client_hello(client_hello: &ClientHello<'_>) -> Self {
        ClientHelloInfo {
            sni: client_hello.server_name().map(|s| s.to_string()),
            alpn: client_hello
                .alpn()
                .map(|iter| iter.map(|s| s.to_vec()).collect())
                .unwrap_or_default(),
            signature_schemes: client_hello
                .signature_schemes()
                .iter()
                .map(|s| u16::from(*s))
                .collect(),
            cipher_suites: client_hello
                .cipher_suites()
                .iter()
                .map(|cs| u16::from(*cs))
                .collect(),
        }
    }
}

/// The TLS settings of a listening endpoint
pub struct TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_source: CertSource,
}

pub enum CertSource {
    Single { cert_path: String, key_path: String },
    Bundle(Vec<BundleCert>),
    Custom(Arc<dyn ResolvesServerCert>),
    AsyncCallback(AsyncCertCallback),
}

pub struct BundleCert {
    pub sni: String,
    pub cert_path: String,
    pub key_path: String,
}

pub struct Acceptor {
    cert_source: CertSource,
    alpn_protocols: Option<Vec<Vec<u8>>>,
}

impl TlsSettings {
    /// Create a Rustls acceptor based on the current setting for certificates,
    /// keys, and protocols.
    ///
    /// For async certificate callbacks, no upfront certificate loading is performed;
    /// certificates are fetched dynamically during the TLS handshake.
    pub fn build(self) -> Acceptor {
        Acceptor {
            cert_source: self.cert_source,
            alpn_protocols: self.alpn_protocols,
        }
    }

    fn build_bundled_config(bundle: &[BundleCert], alpn: Option<&Vec<Vec<u8>>>) -> ServerConfig {
        let crypto_provider = crypto_provider();

        let mut resolver = ResolvesServerCertUsingSni::new();
        for cert_key in bundle {
            let Ok(Some((certs, key))) =
                load_certs_and_key_files(&cert_key.cert_path, &cert_key.key_path)
            else {
                panic!(
                    "Failed to load provided certificates \"{}\" or key \"{}\" for SNI \"{}\".",
                    cert_key.cert_path, cert_key.key_path, cert_key.sni
                )
            };

            let Ok(ck) = CertifiedKey::from_der(certs, key, crypto_provider) else {
                panic!(
                    "Failed to build CertifiedKey from \"{}\" for SNI \"{}\".",
                    cert_key.key_path, cert_key.sni
                )
            };

            if let Err(err) = resolver.add(&cert_key.sni, ck) {
                panic!(
                    "SNI \"{}\" invalid for cert \"{}\" and key \"{}\": {:?}",
                    cert_key.sni, cert_key.cert_path, cert_key.key_path, err
                )
            }
        }

        let mut config =
            ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(resolver));

        if let Some(alpn_protocols) = alpn {
            config.alpn_protocols = alpn_protocols.clone();
        }

        config
    }

    fn build_single_config(
        cert_path: &str,
        key_path: &str,
        alpn: Option<&Vec<Vec<u8>>>,
    ) -> ServerConfig {
        let Ok(Some((certs, key))) = load_certs_and_key_files(cert_path, key_path) else {
            panic!(
                "Failed to load provided certificates \"{}\" or key \"{}\".",
                cert_path, key_path
            )
        };

        let mut config =
            ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .explain_err(InternalError, |e| {
                    format!("Failed to create server listener config: {e}")
                })
                .unwrap();

        if let Some(alpn_protocols) = alpn {
            config.alpn_protocols = alpn_protocols.clone();
        }

        config
    }

    fn build_custom_config(
        resolver: Arc<dyn ResolvesServerCert>,
        alpn: Option<&Vec<Vec<u8>>>,
    ) -> ServerConfig {
        let mut config =
            ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
                .with_no_client_auth()
                .with_cert_resolver(resolver);

        if let Some(alpn_protocols) = alpn {
            config.alpn_protocols = alpn_protocols.clone();
        }

        config
    }

    /// Enable HTTP/2 support for this endpoint, which is default off.
    /// This effectively sets the ALPN to prefer HTTP/2 with HTTP/1.1 allowed
    pub fn enable_h2(&mut self) {
        self.set_alpn(crate::protocols::ALPN::H2H1);
    }

    pub fn set_alpn(&mut self, alpn: crate::protocols::ALPN) {
        self.alpn_protocols = Some(alpn.to_wire_protocols());
    }

    pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(TlsSettings {
            alpn_protocols: None,
            cert_source: CertSource::Single {
                cert_path: cert_path.to_string(),
                key_path: key_path.to_string(),
            },
        })
    }

    pub fn intermediate_bundle(bundle: Vec<BundleCert>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(TlsSettings {
            alpn_protocols: None,
            cert_source: CertSource::Bundle(bundle),
        })
    }

    pub fn intermediate_custom(resolver: Arc<dyn ResolvesServerCert>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(TlsSettings {
            alpn_protocols: None,
            cert_source: CertSource::Custom(resolver),
        })
    }

    /// Create TLS settings with an async callback for fetching certificates.
    ///
    /// The callback receives a `ClientHelloInfo` containing information from
    /// the TLS ClientHello message and should return a future that resolves
    /// to an `Arc<ServerConfig>`.
    ///
    /// This enables asynchronous certificate fetching, useful for scenarios
    /// where certificates need to be loaded from external sources (databases,
    /// remote services, etc.) based on the SNI or other client hello fields.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use pingora_core::listeners::tls::TlsSettings;
    ///
    /// let settings = TlsSettings::with_async_callback(Arc::new(|client_hello| {
    ///     Box::pin(async move {
    ///         // Fetch certificate based on SNI
    ///         let sni = client_hello.sni.as_deref().unwrap_or("default");
    ///         let config = load_config_for_sni(sni).await?;
    ///         Ok(Arc::new(config))
    ///     })
    /// }));
    /// ```
    pub fn with_async_callback(callback: AsyncCertCallback) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(TlsSettings {
            alpn_protocols: None,
            cert_source: CertSource::AsyncCallback(callback),
        })
    }

    pub fn with_callbacks() -> Result<Self>
    where
        Self: Sized,
    {
        Error::e_explain(
            InternalError,
            "Legacy certificate callbacks are not supported. Use with_async_callback instead.",
        )
    }
}

impl Acceptor {
    pub async fn tls_handshake<S: IO>(&self, stream: S) -> Result<TlsStream<S>> {
        debug!("new tls session");

        let lazy_acceptor = LazyConfigAcceptor::new(RusTlsServerAcceptor::default(), stream);

        let start_handshake: StartHandshake<S> = lazy_acceptor
            .await
            .map_err(|e| Error::explain(TLSHandshakeFailure, format!("TLS accept error: {e}")))?;

        let client_hello = start_handshake.client_hello();
        let config = match &self.cert_source {
            CertSource::Single {
                cert_path,
                key_path,
            } => Arc::new(TlsSettings::build_single_config(
                cert_path,
                key_path,
                self.alpn_protocols.as_ref(),
            )),
            CertSource::Bundle(bundle) => Arc::new(TlsSettings::build_bundled_config(
                bundle,
                self.alpn_protocols.as_ref(),
            )),
            CertSource::Custom(resolver) => Arc::new(TlsSettings::build_custom_config(
                resolver.clone(),
                self.alpn_protocols.as_ref(),
            )),
            CertSource::AsyncCallback(callback) => {
                let client_hello_info = ClientHelloInfo::from_client_hello(&client_hello);
                callback(client_hello_info).await?
            }
        };

        let tls_stream = start_handshake
            .into_stream(config)
            .await
            .map_err(|e| Error::explain(TLSHandshakeFailure, format!("TLS handshake error: {e}")))?;

        TlsStream::from_raw(tls_stream).await
    }
}
