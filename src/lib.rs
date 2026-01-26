//! env-lock-rs: .env dosyalarını AES-256-GCM ile şifreleyip kilitleme kütüphanesi
//!
//! Bu modül şifreleme, anahtar türetme ve lock dosya formatı işlemlerini içerir.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Lock dosyasının JSON formatı
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockFile {
    /// Format versiyonu
    pub version: u32,
    /// Şifreleme algoritması
    pub algo: String,
    /// Key derivation function
    pub kdf: String,
    /// Profil adı
    pub profile: String,
    /// Oluşturulma zamanı (ISO8601 UTC)
    pub created_at: DateTime<Utc>,
    /// Salt (base64 encoded)
    pub salt_b64: String,
    /// Nonce (base64 encoded)
    pub nonce_b64: String,
    /// Şifreli veri (base64 encoded)
    pub ciphertext_b64: String,
}

/// Argon2 parametreleri (güvenlik/performans dengesinde ayarlanabilir)
///
/// Varsayılan değerler:
/// - memory_cost: 65536 KB (64 MB) - Bellek kullanımı
/// - time_cost: 3 - İterasyon sayısı
/// - parallelism: 4 - Paralel thread sayısı
pub struct Argon2Params {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

/// Rastgele 16-byte salt üretir
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Rastgele 12-byte nonce üretir (AES-GCM için)
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Password'den Argon2id ile 32-byte anahtar türetir
pub fn derive_key(password: &str, salt: &[u8], params: &Argon2Params) -> Result<[u8; 32]> {
    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| anyhow!("Argon2 parametre hatası: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Anahtar türetme hatası: {}", e))?;

    Ok(key)
}

/// AES-256-GCM ile veriyi şifreler
pub fn encrypt(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("Cipher oluşturma hatası: {}", e))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Şifreleme hatası: {}", e))
}

/// AES-256-GCM ile veriyi çözer
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("Cipher oluşturma hatası: {}", e))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Şifre çözme hatası: Yanlış şifre veya bozuk veri"))
}

/// Dosyayı byte olarak okur (UTF-8 varsayımı yapılmaz)
pub fn read_file_bytes<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    fs::read(&path).with_context(|| format!("Dosya okunamadı: {}", path.as_ref().display()))
}

/// Veriyi dosyaya yazar
pub fn write_file_bytes<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<()> {
    fs::write(&path, data).with_context(|| format!("Dosya yazılamadı: {}", path.as_ref().display()))
}

/// Dosyanın var olup olmadığını kontrol eder
pub fn file_exists<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().exists()
}

/// Bir dosyayı seal (şifrele) eder ve LockFile döner
pub fn seal(
    plaintext: &[u8],
    password: &str,
    profile: &str,
    params: &Argon2Params,
) -> Result<LockFile> {
    let salt = generate_salt();
    let nonce = generate_nonce();
    let key = derive_key(password, &salt, params)?;
    let ciphertext = encrypt(plaintext, &key, &nonce)?;

    Ok(LockFile {
        version: 1,
        algo: "aes-256-gcm".to_string(),
        kdf: "argon2id".to_string(),
        profile: profile.to_string(),
        created_at: Utc::now(),
        salt_b64: BASE64.encode(salt),
        nonce_b64: BASE64.encode(nonce),
        ciphertext_b64: BASE64.encode(&ciphertext),
    })
}

/// LockFile'ı JSON string'e serialize eder
pub fn lock_to_json(lock: &LockFile) -> Result<String> {
    serde_json::to_string_pretty(lock).context("JSON serialize hatası")
}

/// JSON string'den LockFile parse eder
pub fn json_to_lock(json: &str) -> Result<LockFile> {
    serde_json::from_str(json).context("JSON parse hatası: Geçersiz lock dosyası formatı")
}

/// LockFile'ı open (şifre çöz) eder
pub fn open(
    lock: &LockFile,
    password: &str,
    expected_profile: Option<&str>,
    params: &Argon2Params,
) -> Result<Vec<u8>> {
    // Profil kontrolü
    if let Some(expected) = expected_profile {
        if lock.profile != expected {
            bail!(
                "Profil uyuşmazlığı: Beklenen '{}', dosyada '{}'",
                expected,
                lock.profile
            );
        }
    }

    // Base64 decode
    let salt = BASE64
        .decode(&lock.salt_b64)
        .context("Salt decode hatası")?;
    let nonce = BASE64
        .decode(&lock.nonce_b64)
        .context("Nonce decode hatası")?;
    let ciphertext = BASE64
        .decode(&lock.ciphertext_b64)
        .context("Ciphertext decode hatası")?;

    // Salt ve nonce boyut kontrolü
    let salt: [u8; 16] = salt
        .try_into()
        .map_err(|_| anyhow!("Geçersiz salt boyutu"))?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| anyhow!("Geçersiz nonce boyutu"))?;

    // Anahtar türet ve şifreyi çöz
    let key = derive_key(password, &salt, params)?;
    decrypt(&ciphertext, &key, &nonce)
}

/// Lock dosyasının metadata bilgilerini formatlar
pub fn format_status(lock: &LockFile) -> String {
    format!(
        "Version:    {}\n\
         Algorithm:  {}\n\
         KDF:        {}\n\
         Profile:    {}\n\
         Created:    {}",
        lock.version,
        lock.algo,
        lock.kdf,
        lock.profile,
        lock.created_at.format("%Y-%m-%dT%H:%M:%SZ")
    )
}

/// Password'ü öncelik sırasına göre alır:
/// 1. Explicit password (--password argümanı)
/// 2. ENV_LOCK_KEY environment variable
/// 3. Hata döner
pub fn get_password(explicit: Option<&str>) -> Result<String> {
    if let Some(pw) = explicit {
        return Ok(pw.to_string());
    }

    if let Ok(pw) = std::env::var("ENV_LOCK_KEY") {
        if !pw.is_empty() {
            return Ok(pw);
        }
    }

    bail!(
        "Şifre belirtilmedi!\n\
         Kullanım: --password <şifre> veya ENV_LOCK_KEY ortam değişkenini ayarlayın"
    )
}

/// Seal komutu için varsayılan output path üretir
pub fn default_seal_output<P: AsRef<Path>>(input: P) -> String {
    format!("{}.lock", input.as_ref().display())
}

/// Open komutu için varsayılan output path üretir
pub fn default_open_output<P: AsRef<Path>>(lock_path: P) -> String {
    let path = lock_path.as_ref();
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();

    if stem.is_empty() {
        "output.env".to_string()
    } else {
        format!("{}.out", path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const TEST_PASSWORD: &str = "test-password-123";
    const TEST_PROFILE: &str = "test-profile";

    // Test için hızlı Argon2 parametreleri
    fn fast_params() -> Argon2Params {
        Argon2Params {
            memory_cost: 4096, // 4 MB (test için düşük)
            time_cost: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn test_roundtrip() {
        let original = b"DATABASE_URL=postgres://localhost/test\nSECRET_KEY=abc123\n";

        // Seal
        let lock = seal(original, TEST_PASSWORD, TEST_PROFILE, &fast_params()).unwrap();

        // JSON roundtrip
        let json = lock_to_json(&lock).unwrap();
        let lock_parsed = json_to_lock(&json).unwrap();

        // Open
        let decrypted = open(&lock_parsed, TEST_PASSWORD, None, &fast_params()).unwrap();

        assert_eq!(original.to_vec(), decrypted);
    }

    #[test]
    fn test_roundtrip_with_file() {
        let dir = tempdir().unwrap();
        let input_path = dir.path().join(".env");
        let lock_path = dir.path().join(".env.lock");
        let output_path = dir.path().join(".env.out");

        let original = b"API_KEY=secret_value_123\nDEBUG=true\n";

        // Write input file
        write_file_bytes(&input_path, original).unwrap();

        // Read and seal
        let data = read_file_bytes(&input_path).unwrap();
        let lock = seal(&data, TEST_PASSWORD, "default", &fast_params()).unwrap();
        let json = lock_to_json(&lock).unwrap();
        write_file_bytes(&lock_path, json.as_bytes()).unwrap();

        // Read lock and open
        let lock_data = read_file_bytes(&lock_path).unwrap();
        let lock_json = String::from_utf8(lock_data).unwrap();
        let lock_parsed = json_to_lock(&lock_json).unwrap();
        let decrypted = open(&lock_parsed, TEST_PASSWORD, None, &fast_params()).unwrap();
        write_file_bytes(&output_path, &decrypted).unwrap();

        // Verify
        let output_data = read_file_bytes(&output_path).unwrap();
        assert_eq!(original.to_vec(), output_data);
    }

    #[test]
    fn test_wrong_password_fails() {
        let original = b"SECRET=value";

        let lock = seal(original, TEST_PASSWORD, TEST_PROFILE, &fast_params()).unwrap();

        let result = open(&lock, "wrong-password", None, &fast_params());

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Şifre çözme hatası"));
    }

    #[test]
    fn test_profile_mismatch_fails() {
        let original = b"DATA=test";

        let lock = seal(original, TEST_PASSWORD, "profile-a", &fast_params()).unwrap();

        let result = open(&lock, TEST_PASSWORD, Some("profile-b"), &fast_params());

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Profil uyuşmazlığı"));
    }

    #[test]
    fn test_profile_match_succeeds() {
        let original = b"DATA=test";

        let lock = seal(original, TEST_PASSWORD, TEST_PROFILE, &fast_params()).unwrap();
        let decrypted = open(&lock, TEST_PASSWORD, Some(TEST_PROFILE), &fast_params()).unwrap();

        assert_eq!(original.to_vec(), decrypted);
    }

    #[test]
    fn test_binary_data_roundtrip() {
        // Binary data (non-UTF8)
        let original: Vec<u8> = (0..=255).collect();

        let lock = seal(&original, TEST_PASSWORD, TEST_PROFILE, &fast_params()).unwrap();
        let decrypted = open(&lock, TEST_PASSWORD, None, &fast_params()).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_empty_data_roundtrip() {
        let original = b"";

        let lock = seal(original, TEST_PASSWORD, TEST_PROFILE, &fast_params()).unwrap();
        let decrypted = open(&lock, TEST_PASSWORD, None, &fast_params()).unwrap();

        assert_eq!(original.to_vec(), decrypted);
    }

    #[test]
    fn test_lock_file_format() {
        let lock = seal(b"test", TEST_PASSWORD, "my-profile", &fast_params()).unwrap();

        assert_eq!(lock.version, 1);
        assert_eq!(lock.algo, "aes-256-gcm");
        assert_eq!(lock.kdf, "argon2id");
        assert_eq!(lock.profile, "my-profile");
    }

    #[test]
    fn test_default_seal_output() {
        assert_eq!(default_seal_output(".env"), ".env.lock");
        assert_eq!(default_seal_output("config/app.env"), "config/app.env.lock");
    }

    #[test]
    fn test_default_open_output() {
        assert_eq!(default_open_output(".env.lock"), ".env.lock.out");
        assert_eq!(
            default_open_output("config/app.env.lock"),
            "config/app.env.lock.out"
        );
    }

    #[test]
    fn test_get_password_explicit() {
        let pw = get_password(Some("explicit-pw")).unwrap();
        assert_eq!(pw, "explicit-pw");
    }

    #[test]
    fn test_get_password_missing() {
        // ENV_LOCK_KEY olmadığından emin ol
        std::env::remove_var("ENV_LOCK_KEY");

        let result = get_password(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_status() {
        let lock = seal(b"test", TEST_PASSWORD, "prod", &fast_params()).unwrap();
        let status = format_status(&lock);

        assert!(status.contains("Version:    1"));
        assert!(status.contains("Algorithm:  aes-256-gcm"));
        assert!(status.contains("KDF:        argon2id"));
        assert!(status.contains("Profile:    prod"));
    }
}
