use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use log::{debug, error, info, warn};
use pingora_error::{Error, ErrorType, OrErr, Result};
use pingora_rustls::{
    crypto_provider, load_certs_and_key_files, CertifiedKey, ResolvesServerCert, ClientHello,
};

#[derive(Debug, Clone)]
pub struct DynamicCertResolver {
    certificates: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
    default_cert: Option<Arc<CertifiedKey>>,
}

impl DynamicCertResolver {
    pub fn new() -> Self {
        Self {
            certificates: Arc::new(RwLock::new(HashMap::new())),
            default_cert: None,
        }
    }

    pub fn new_with_default(default_cert: Arc<CertifiedKey>) -> Self {
        Self {
            certificates: Arc::new(RwLock::new(HashMap::new())),
            default_cert: Some(default_cert),
        }
    }

    pub fn add_cert_from_files(&self, sni: &str, cert_path: &str, key_path: &str) -> Result<()> {
        let crypto_provider = crypto_provider();
        
        let (certs, key) = load_certs_and_key_files(cert_path, key_path)?
            .ok_or_else(|| {
                Error::explain(
                    ErrorType::InvalidCert,
                    format!("Failed to load cert '{}' or key '{}'", cert_path, key_path)
                )
            })?;

        let certified_key = CertifiedKey::from_der(certs, key, crypto_provider)
            .or_err(ErrorType::InvalidCert, "Failed to create CertifiedKey from DER")?;

        self.add_cert(sni, Arc::new(certified_key))
    }

    pub fn add_cert(&self, sni: &str, cert: Arc<CertifiedKey>) -> Result<()> {
        let normalized_sni = sni.to_lowercase();

        match self.certificates.write() {
            Ok(mut certs) => {
                if certs.insert(normalized_sni.clone(), cert).is_some() {
                    info!("Updated certificate for SNI: {}", normalized_sni);
                } else {
                    info!("Added certificate for SNI: {}", normalized_sni);
                }
                Ok(())
            }
            Err(e) => {
                error!("Failed to acquire write lock for certificates: {}", e);
                Error::e_explain(
                    ErrorType::InternalError,
                    "Failed to acquire write lock for certificate storage"
                )
            }
        }
    }

    pub fn remove_cert(&self, sni: &str) -> Result<bool> {
        let normalized_sni = sni.to_lowercase();
        
        match self.certificates.write() {
            Ok(mut certs) => {
                if certs.remove(&normalized_sni).is_some() {
                    info!("Removed certificate for SNI: {}", normalized_sni);
                    Ok(true)
                } else {
                    warn!("Certificate not found for SNI: {}", normalized_sni);
                    Ok(false)
                }
            }
            Err(e) => {
                error!("Failed to acquire write lock for certificates: {}", e);
                Error::e_explain(
                    ErrorType::InternalError,
                    "Failed to acquire write lock for certificate storage"
                )
            }
        }
    }

    pub fn get_cert(&self, sni: &str) -> Result<Option<Arc<CertifiedKey>>> {
        let normalized_sni = sni.to_lowercase();
        
        match self.certificates.read() {
            Ok(certs) => Ok(certs.get(&normalized_sni).cloned()),
            Err(e) => {
                error!("Failed to acquire read lock for certificates: {}", e);
                Error::e_explain(
                    ErrorType::InternalError,
                    "Failed to acquire read lock for certificate storage"
                )
            }
        }
    }

    pub fn list_snis(&self) -> Result<Vec<String>> {
        match self.certificates.read() {
            Ok(certs) => Ok(certs.keys().cloned().collect()),
            Err(e) => {
                error!("Failed to acquire read lock for certificates: {}", e);
                Error::e_explain(
                    ErrorType::InternalError,
                    "Failed to acquire read lock for certificate storage"
                )
            }
        }
    }

    pub fn cert_count(&self) -> Result<usize> {
        match self.certificates.read() {
            Ok(certs) => Ok(certs.len()),
            Err(e) => {
                error!("Failed to acquire read lock for certificates: {}", e);
                Error::e_explain(
                    ErrorType::InternalError,
                    "Failed to acquire read lock for certificate storage"
                )
            }
        }
    }

    pub fn clear_all(&self) -> Result<()> {
        match self.certificates.write() {
            Ok(mut certs) => {
                let count = certs.len();
                certs.clear();
                info!("Cleared {} certificates", count);
                Ok(())
            }
            Err(e) => {
                error!("Failed to acquire write lock for certificates: {}", e);
                Error::e_explain(
                    ErrorType::InternalError,
                    "Failed to acquire write lock for certificate storage"
                )
            }
        }
    }

    pub fn set_default_cert(&mut self, cert: Arc<CertifiedKey>) {
        self.default_cert = Some(cert);
        info!("Set default certificate");
    }

    pub fn set_default_cert_from_files(&mut self, cert_path: &str, key_path: &str) -> Result<()> {
        let crypto_provider = crypto_provider();
        
        let (certs, key) = load_certs_and_key_files(cert_path, key_path)?
            .ok_or_else(|| {
                Error::explain(
                    ErrorType::InvalidCert,
                    format!("Failed to load default cert '{}' or key '{}'", cert_path, key_path)
                )
            })?;

        let certified_key = CertifiedKey::from_der(certs, key, crypto_provider)
            .or_err(ErrorType::InvalidCert, "Failed to create default CertifiedKey from DER")?;

        self.set_default_cert(Arc::new(certified_key));
        Ok(())
    }

    fn matches_wildcard(pattern: &str, hostname: &str) -> bool {
        if pattern.starts_with("*.") {
            let domain = &pattern[2..];
            hostname.ends_with(domain) && hostname.len() > domain.len() && hostname.chars().nth(hostname.len() - domain.len() - 1) == Some('.')
        } else {
            pattern == hostname
        }
    }

    fn find_best_match(&self, hostname: &str) -> Option<Arc<CertifiedKey>> {
        let normalized_hostname = hostname.to_lowercase();
        
        match self.certificates.read() {
            Ok(certs) => {
                if let Some(cert) = certs.get(&normalized_hostname) {
                    debug!("Found exact match for hostname: {}", normalized_hostname);
                    return Some(cert.clone());
                }

                for (pattern, cert) in certs.iter() {
                    if Self::matches_wildcard(pattern, &normalized_hostname) {
                        debug!("Found wildcard match '{}' for hostname: {}", pattern, normalized_hostname);
                        return Some(cert.clone());
                    }
                }

                debug!("No certificate match found for hostname: {}", normalized_hostname);
                None
            }
            Err(e) => {
                error!("Failed to acquire read lock for certificates: {}", e);
                None
            }
        }
    }
}

impl Default for DynamicCertResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name();

        debug!("Resolving certificate for SNI: {:?}", sni);

        match sni {
            Some(name) => {
                let hostname = name.as_ref();
                self.find_best_match(hostname)
                    .or_else(|| {
                        debug!("No specific certificate found for '{}', using default", hostname);
                        self.default_cert.clone()
                    })
            }
            None => {
                debug!("No SNI provided, using default certificate");
                self.default_cert.clone()
            }
        }
    }
}