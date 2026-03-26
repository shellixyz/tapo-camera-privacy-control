#![warn(clippy::pedantic)]
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use md5::{Digest as Md5Digest, Md5};
use rand::RngExt;
use reqwest::header::{HeaderMap, HeaderValue};
use sha2::Sha256;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use thiserror::Error;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Error, Debug)]
pub enum TapoError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Authentication failed: {0}")]
    Auth(String),
    #[error("Device error (code {code}): {message}")]
    Device { code: i64, message: String },
    #[error("Encryption error: {0}")]
    Crypto(String),
}

#[derive(Debug, Clone, Copy)]
pub enum PrivacyMode {
    On,
    Off,
}

impl std::fmt::Display for PrivacyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivacyMode::On => write!(f, "on"),
            PrivacyMode::Off => write!(f, "off"),
        }
    }
}

/// Session state after successful authentication.
struct Session {
    stok: String,
    /// Only present for secure (`encrypt_type` 3) connections.
    crypto: Option<CryptoState>,
}

struct CryptoState {
    lsk: [u8; 16],
    ivb: [u8; 16],
    seq: AtomicI64,
    tag_prefix: String, // SHA256(hashed_password + cnonce), uppercased hex
}

pub struct TapoCamera {
    ip: String,
    username: String,
    password: String,
    client: reqwest::Client,
    /// If `None`, the reqwest client's default timeout is used.
    timeout: Option<Duration>,
    session: Option<Session>,
}

impl TapoCamera {
    /// Create a new `TapoCamera` client.
    ///
    /// The client is configured to accept invalid TLS certificates
    /// (useful for local camera devices that present self-signed certs).
    ///
    /// The client uses reqwest's default timeout unless changed with
    /// `set_timeout`.
    ///
    /// # Errors
    /// Returns an error if the underlying HTTP client cannot be built.
    pub fn new(
        ip: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {e}"))?;

        Ok(Self {
            ip: ip.into(),
            username: username.into(),
            password: password.into(),
            client,
            timeout: None,
            session: None,
        })
    }

    /// Get the current request timeout used by the HTTP client.
    ///
    /// If `None` is returned, the client is using reqwest's default timeout.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Set a new request timeout and rebuild the underlying HTTP client.
    ///
    /// Passing `None` resets the client to use reqwest's default timeout.
    ///
    /// # Errors
    /// Returns an error if rebuilding the HTTP client fails.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) -> anyhow::Result<()> {
        let mut builder = reqwest::Client::builder().danger_accept_invalid_certs(true);
        if let Some(t) = timeout {
            builder = builder.timeout(t);
        }
        let client = builder
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {e}"))?;

        self.client = client;
        self.timeout = timeout;
        Ok(())
    }

    fn base_url(&self) -> String {
        format!("https://{}:443", self.ip)
    }

    fn default_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "User-Agent",
            HeaderValue::from_static("Tapo CameraClient Android"),
        );
        h.insert("requestByApp", HeaderValue::from_static("true"));
        h
    }

    fn hash_md5(input: &str) -> String {
        let mut hasher = Md5::new();
        hasher.update(input.as_bytes());
        hasher
            .finalize()
            .iter()
            .fold(String::new(), |mut output, b| {
                let _ = write!(output, "{b:02X}");
                output
            })
    }

    fn hash_sha256(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hasher
            .finalize()
            .iter()
            .fold(String::new(), |mut output, b| {
                let _ = write!(output, "{b:02X}");
                output
            })
    }

    fn hash_sha256_bytes(input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }

    fn generate_cnonce() -> String {
        let bytes: [u8; 8] = rand::rng().random();
        bytes.iter().fold(String::new(), |mut output, b| {
            let _ = write!(output, "{b:02X}");
            output
        })
    }

    /// Authenticate with the camera. Must be called before sending commands.
    ///
    /// # Errors
    /// - Returns `TapoError::Http` if the HTTP request fails.
    /// - Returns `TapoError::Json` if the camera response cannot be parsed as JSON.
    /// - Returns `TapoError::Auth` for authentication-related failures (bad password,
    ///   missing fields in the challenge/response, or non-zero error codes from the
    ///   device).
    pub async fn login(&mut self) -> Result<(), TapoError> {
        let cnonce = Self::generate_cnonce();

        // Step 1: Probe for secure connection support
        let probe = serde_json::json!({
            "method": "login",
            "params": {
                "encrypt_type": "3",
                "username": self.username,
                "cnonce": cnonce
            }
        });

        let resp: serde_json::Value = self
            .client
            .post(self.base_url())
            .headers(Self::default_headers())
            .json(&probe)
            .send()
            .await?
            .json()
            .await?;

        let error_code = resp["error_code"].as_i64().unwrap_or(0);

        if error_code == -40413 {
            // Check if encrypt_type 3 is supported
            let encrypt_types = &resp["result"]["data"]["encrypt_type"];
            let supports_secure = if let Some(arr) = encrypt_types.as_array() {
                arr.iter().any(|v| v.as_str() == Some("3"))
            } else {
                false
            };

            if supports_secure {
                self.login_secure(&cnonce, &resp).await
            } else {
                self.login_insecure().await
            }
        } else {
            // Camera might not support the probe — try insecure
            self.login_insecure().await
        }
    }

    async fn login_secure(
        &mut self,
        cnonce: &str,
        challenge_resp: &serde_json::Value,
    ) -> Result<(), TapoError> {
        let device_nonce = challenge_resp["result"]["data"]["nonce"]
            .as_str()
            .ok_or_else(|| TapoError::Auth("missing nonce in challenge".into()))?;
        let device_confirm = challenge_resp["result"]["data"]["device_confirm"]
            .as_str()
            .ok_or_else(|| TapoError::Auth("missing device_confirm".into()))?;

        // Determine password hash method by checking device_confirm
        let md5_hash = Self::hash_md5(&self.password);
        let sha256_hash = Self::hash_sha256(&self.password);

        let hashed_nonces_sha256 =
            Self::hash_sha256(&format!("{cnonce}{sha256_hash}{device_nonce}"));
        let hashed_nonces_md5 = Self::hash_sha256(&format!("{cnonce}{md5_hash}{device_nonce}"));

        let expected_confirm_sha256 = format!("{hashed_nonces_sha256}{device_nonce}{cnonce}");
        let expected_confirm_md5 = format!("{hashed_nonces_md5}{device_nonce}{cnonce}");

        // eprintln!("[debug] cnonce:          {}", cnonce);
        // eprintln!("[debug] device_nonce:    {}", device_nonce);
        // eprintln!("[debug] device_confirm:  {}", device_confirm);
        // eprintln!("[debug] confirm len:     {}", device_confirm.len());
        // eprintln!("[debug] expected (sha256): {}", expected_confirm_sha256);
        // eprintln!("[debug] expected (md5):    {}", expected_confirm_md5);
        // eprintln!("[debug] sha256(pass):    {}", sha256_hash);
        // eprintln!("[debug] md5(pass):       {}", md5_hash);

        let hashed_password = if device_confirm == expected_confirm_sha256 {
            sha256_hash
        } else if device_confirm == expected_confirm_md5 {
            md5_hash
        } else {
            return Err(TapoError::Auth(
                "device_confirm mismatch — wrong password?".into(),
            ));
        };

        // Compute digest_passwd
        let digest = Self::hash_sha256(&format!("{hashed_password}{cnonce}{device_nonce}"));
        let digest_passwd = format!("{digest}{cnonce}{device_nonce}");

        let login_req = serde_json::json!({
            "method": "login",
            "params": {
                "cnonce": cnonce,
                "encrypt_type": "3",
                "digest_passwd": digest_passwd,
                "username": self.username
            }
        });

        let resp: serde_json::Value = self
            .client
            .post(self.base_url())
            .headers(Self::default_headers())
            .json(&login_req)
            .send()
            .await?
            .json()
            .await?;

        let error_code = resp["error_code"].as_i64().unwrap_or(-1);
        if error_code != 0 {
            return Err(TapoError::Auth(format!(
                "login failed with error_code {error_code}"
            )));
        }

        let stok = resp["result"]["stok"]
            .as_str()
            .ok_or_else(|| TapoError::Auth("missing stok in login response".into()))?
            .to_string();

        let start_seq = resp["result"]["start_seq"].as_i64().unwrap_or(0);

        // Derive AES keys
        let hashed_key = Self::hash_sha256(&format!("{cnonce}{hashed_password}{device_nonce}"));

        let lsk_full =
            Self::hash_sha256_bytes(format!("lsk{cnonce}{device_nonce}{hashed_key}").as_bytes());
        let ivb_full =
            Self::hash_sha256_bytes(format!("ivb{cnonce}{device_nonce}{hashed_key}").as_bytes());

        let mut lsk = [0u8; 16];
        let mut ivb = [0u8; 16];
        lsk.copy_from_slice(&lsk_full[..16]);
        ivb.copy_from_slice(&ivb_full[..16]);

        let tag_prefix = Self::hash_sha256(&format!("{hashed_password}{cnonce}"));

        self.session = Some(Session {
            stok,
            crypto: Some(CryptoState {
                lsk,
                ivb,
                seq: AtomicI64::new(start_seq),
                tag_prefix,
            }),
        });

        Ok(())
    }

    async fn login_insecure(&mut self) -> Result<(), TapoError> {
        let hashed_password = Self::hash_md5(&self.password);

        let login_req = serde_json::json!({
            "method": "login",
            "params": {
                "hashed": true,
                "password": hashed_password,
                "username": self.username
            }
        });

        let resp: serde_json::Value = self
            .client
            .post(self.base_url())
            .headers(Self::default_headers())
            .json(&login_req)
            .send()
            .await?
            .json()
            .await?;

        let error_code = resp["error_code"].as_i64().unwrap_or(-1);
        if error_code != 0 {
            return Err(TapoError::Auth(format!(
                "insecure login failed with error_code {error_code}"
            )));
        }

        let stok = resp["result"]["stok"]
            .as_str()
            .ok_or_else(|| TapoError::Auth("missing stok".into()))?
            .to_string();

        self.session = Some(Session { stok, crypto: None });

        Ok(())
    }

    fn encrypt(crypto: &CryptoState, plaintext: &[u8]) -> Result<Vec<u8>, TapoError> {
        let enc = Aes128CbcEnc::new(&crypto.lsk.into(), &crypto.ivb.into());
        // Allocate buffer with space for padding (up to one extra block)
        let block_size = 16;
        let padded_len = (plaintext.len() / block_size + 1) * block_size;
        let mut buf = vec![0u8; padded_len];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct = enc
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .map_err(|e| TapoError::Crypto(format!("encryption failed: {e}")))?;
        Ok(ct.to_vec())
    }

    fn decrypt(crypto: &CryptoState, ciphertext: &[u8]) -> Result<Vec<u8>, TapoError> {
        let dec = Aes128CbcDec::new(&crypto.lsk.into(), &crypto.ivb.into());
        let mut buf = ciphertext.to_vec();
        let pt = dec
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| TapoError::Crypto(format!("decryption failed: {e}")))?;
        Ok(pt.to_vec())
    }

    fn compute_tag(crypto: &CryptoState, body: &str, seq: i64) -> String {
        Self::hash_sha256(&format!("{}{}{}", crypto.tag_prefix, body, seq))
    }

    /// Send a command to the camera. Handles encryption if using secure mode.
    async fn send_command(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TapoError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| TapoError::Auth("not logged in — call login() first".into()))?;

        let url = format!("{}/stok={}/ds", self.base_url(), session.stok);

        if let Some(crypto) = &session.crypto {
            let inner_json = serde_json::to_string(&payload)?;
            let encrypted = Self::encrypt(crypto, inner_json.as_bytes())?;
            let encoded = BASE64.encode(&encrypted);

            let outer = serde_json::json!({
                "method": "securePassthrough",
                "params": {
                    "request": encoded
                }
            });

            let seq = crypto.seq.fetch_add(1, Ordering::SeqCst);
            let outer_str = serde_json::to_string(&outer)?;
            let tag = Self::compute_tag(crypto, &outer_str, seq);

            let mut headers = Self::default_headers();
            headers.insert("Seq", HeaderValue::from_str(&seq.to_string()).unwrap());
            headers.insert("Tapo_tag", HeaderValue::from_str(&tag).unwrap());

            let resp: serde_json::Value = self
                .client
                .post(&url)
                .headers(headers)
                .json(&outer)
                .send()
                .await?
                .json()
                .await?;

            let error_code = resp["error_code"].as_i64().unwrap_or(0);
            if error_code != 0 {
                return Err(TapoError::Device {
                    code: error_code,
                    message: format!("securePassthrough failed: {resp:?}"),
                });
            }

            let encrypted_resp =
                resp["result"]["response"]
                    .as_str()
                    .ok_or_else(|| TapoError::Device {
                        code: -1,
                        message: "missing encrypted response".into(),
                    })?;

            let decoded = BASE64
                .decode(encrypted_resp)
                .map_err(|e| TapoError::Crypto(format!("base64 decode failed: {e}")))?;
            let decrypted = Self::decrypt(crypto, &decoded)?;
            let result: serde_json::Value = serde_json::from_slice(&decrypted)?;

            Ok(result)
        } else {
            // Insecure mode: send plaintext
            let resp: serde_json::Value = self
                .client
                .post(&url)
                .headers(Self::default_headers())
                .json(&payload)
                .send()
                .await?
                .json()
                .await?;

            Ok(resp)
        }
    }

    fn wrap_command(method: &str, params: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "method": "multipleRequest",
            "params": {
                "requests": [{
                    "method": method,
                    "params": params
                }]
            }
        })
    }

    /// Set privacy mode (lens mask) on or off.
    ///
    /// # Errors
    /// - Returns `TapoError::Auth` if not logged in.
    /// - Returns `TapoError::Http`/`TapoError::Json` for transport or parsing errors.
    /// - Returns `TapoError::Device` if the camera returns a non-zero error code for
    ///   the `setLensMaskConfig` request.
    pub async fn set_privacy_mode(&self, mode: PrivacyMode) -> Result<(), TapoError> {
        let value = match mode {
            PrivacyMode::On => "on",
            PrivacyMode::Off => "off",
        };

        let cmd = Self::wrap_command(
            "setLensMaskConfig",
            &serde_json::json!({
                "lens_mask": {
                    "lens_mask_info": {
                        "enabled": value
                    }
                }
            }),
        );

        let resp = self.send_command(cmd).await?;

        // Check inner response error code
        if let Some(responses) = resp["result"]["responses"].as_array() {
            if let Some(first) = responses.first() {
                let code = first["error_code"].as_i64().unwrap_or(0);
                if code != 0 {
                    return Err(TapoError::Device {
                        code,
                        message: format!("setLensMaskConfig failed: {first:?}"),
                    });
                }
            }
        }

        Ok(())
    }

    /// Get current privacy mode status.
    ///
    /// # Errors
    /// - Returns `TapoError::Auth` if not logged in.
    /// - Returns `TapoError::Http`/`TapoError::Json` for transport or parsing errors.
    /// - Returns `TapoError::Device` if the camera returns a non-zero error code for
    ///   the `getLensMaskConfig` request or if the expected fields are missing.
    pub async fn get_privacy_mode(&self) -> Result<PrivacyMode, TapoError> {
        let cmd = Self::wrap_command(
            "getLensMaskConfig",
            &serde_json::json!({
                "lens_mask": {
                    "name": ["lens_mask_info"]
                }
            }),
        );

        let resp = self.send_command(cmd).await?;

        let enabled = resp["result"]["responses"][0]["result"]["lens_mask"]["lens_mask_info"]
            ["enabled"]
            .as_str()
            .unwrap_or("off");

        Ok(if enabled == "on" {
            PrivacyMode::On
        } else {
            PrivacyMode::Off
        })
    }
}
