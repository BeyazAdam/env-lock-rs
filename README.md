# env-lock-rs

[![CI](https://github.com/BeyazAdam/env-lock-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/BeyazAdam/env-lock-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

> **EN** | [TR](#türkçe)

A command-line tool to seal (encrypt) and open (decrypt) `.env` files using **AES-256-GCM** encryption with **Argon2id** key derivation.

## Features

- **Strong Encryption**: AES-256-GCM authenticated encryption
- **Secure Key Derivation**: Argon2id with configurable memory/time costs
- **Profile Support**: Tag lock files with profile names for environment separation
- **Byte-Safe**: Handles binary data without UTF-8 assumptions
- **JSON Output**: Human-readable lock file format with metadata

## Installation

### From crates.io (coming soon)

```bash
cargo install env-lock-rs
```

### From source

```bash
git clone https://github.com/BeyazAdam/env-lock-rs.git
cd env-lock-rs
cargo install --path .
```

Or build directly:

```bash
cargo build --release
# Binary will be at ./target/release/env-lock
```

## Usage

### Seal (Encrypt) a File

```bash
# Basic usage
env-lock seal .env --password "your-secret-password"

# Output to specific file
env-lock seal .env --out production.env.lock --password "secret"

# Use profile for environment separation
env-lock seal .env --profile production --password "secret"

# Output to stdout
env-lock seal .env --password "secret" --stdout > backup.lock

# Force overwrite existing file
env-lock seal .env --password "secret" --force
```

### Open (Decrypt) a File

```bash
# Basic usage
env-lock open .env.lock --password "your-secret-password"

# Output to specific file
env-lock open .env.lock --out .env.restored --password "secret"

# Verify profile before decrypting
env-lock open production.env.lock --profile production --password "secret"

# Output to stdout
env-lock open .env.lock --password "secret" --stdout

# Force overwrite existing file
env-lock open .env.lock --password "secret" --force
```

### Check Lock File Status

```bash
env-lock status .env.lock
```

Output:
```
Version:    1
Algorithm:  aes-256-gcm
KDF:        argon2id
Profile:    production
Created:    2026-01-26T12:00:00Z
```

## Password Sources

Passwords are resolved in this priority order:

1. `--password` command-line argument
2. `ENV_LOCK_KEY` environment variable
3. Error if neither is provided

```bash
# Using environment variable
export ENV_LOCK_KEY="my-secret"
env-lock seal .env
env-lock open .env.lock
```

## Lock File Format

```json
{
  "version": 1,
  "algo": "aes-256-gcm",
  "kdf": "argon2id",
  "profile": "default",
  "created_at": "2026-01-26T12:00:00Z",
  "salt_b64": "...",
  "nonce_b64": "...",
  "ciphertext_b64": "..."
}
```

## Security Considerations

This tool uses **real cryptographic algorithms**:

- **AES-256-GCM**: Industry-standard authenticated encryption
- **Argon2id**: Winner of the Password Hashing Competition, resistant to GPU/ASIC attacks
- **Random Nonce**: 12-byte cryptographically secure random nonce per encryption
- **Random Salt**: 16-byte cryptographically secure random salt per encryption

**However**, security depends on proper usage:

⚠️ **Use strong, unique passwords** — weak passwords are vulnerable to dictionary attacks  
⚠️ **Protect your lock files** — encrypted data can still be attacked offline  
⚠️ **This is not a replacement for proper secrets management** (HashiCorp Vault, AWS Secrets Manager, etc.) for production environments  
⚠️ **Backup your passwords** — there is no recovery mechanism if you lose the password  

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

```bash
# Run tests
cargo test

# Run clippy
cargo clippy -- -D warnings

# Format code
cargo fmt
```

---

<a name="türkçe"></a>

# env-lock-rs

[![CI](https://github.com/BeyazAdam/env-lock-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/BeyazAdam/env-lock-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

> [EN](#env-lock-rs) | **TR**

`.env` dosyalarını **AES-256-GCM** şifreleme ve **Argon2id** anahtar türetme ile kilitleyen (seal) ve açan (open) komut satırı aracı.

## Özellikler

- **Güçlü Şifreleme**: AES-256-GCM kimlik doğrulamalı şifreleme
- **Güvenli Anahtar Türetme**: Ayarlanabilir bellek/zaman maliyetli Argon2id
- **Profil Desteği**: Ortam ayırımı için lock dosyalarını profil isimleriyle etiketleme
- **Byte-Güvenli**: UTF-8 varsayımı yapmadan binary veri işleme
- **JSON Çıktı**: Metadata ile insan tarafından okunabilir lock dosya formatı

## Kurulum

### crates.io'dan (yakında)

```bash
cargo install env-lock-rs
```

### Kaynaktan

```bash
git clone https://github.com/BeyazAdam/env-lock-rs.git
cd env-lock-rs
cargo install --path .
```

Veya doğrudan derleyin:

```bash
cargo build --release
# Binary ./target/release/env-lock konumunda olacak
```

## Kullanım

### Seal (Şifrele)

```bash
# Temel kullanım
env-lock seal .env --password "gizli-sifreniz"

# Belirli dosyaya çıktı
env-lock seal .env --out production.env.lock --password "gizli"

# Ortam ayırımı için profil kullanımı
env-lock seal .env --profile production --password "gizli"

# stdout'a çıktı
env-lock seal .env --password "gizli" --stdout > backup.lock

# Mevcut dosyanın üzerine yazma
env-lock seal .env --password "gizli" --force
```

### Open (Şifre Çöz)

```bash
# Temel kullanım
env-lock open .env.lock --password "gizli-sifreniz"

# Belirli dosyaya çıktı
env-lock open .env.lock --out .env.restored --password "gizli"

# Şifre çözmeden önce profil doğrulama
env-lock open production.env.lock --profile production --password "gizli"

# stdout'a çıktı
env-lock open .env.lock --password "gizli" --stdout

# Mevcut dosyanın üzerine yazma
env-lock open .env.lock --password "gizli" --force
```

### Lock Dosyası Durumu

```bash
env-lock status .env.lock
```

Çıktı:
```
Version:    1
Algorithm:  aes-256-gcm
KDF:        argon2id
Profile:    production
Created:    2026-01-26T12:00:00Z
```

## Şifre Kaynakları

Şifreler şu öncelik sırasıyla alınır:

1. `--password` komut satırı argümanı
2. `ENV_LOCK_KEY` ortam değişkeni
3. Hiçbiri yoksa hata

```bash
# Ortam değişkeni kullanımı
export ENV_LOCK_KEY="gizli-sifrem"
env-lock seal .env
env-lock open .env.lock
```

## Lock Dosya Formatı

```json
{
  "version": 1,
  "algo": "aes-256-gcm",
  "kdf": "argon2id",
  "profile": "default",
  "created_at": "2026-01-26T12:00:00Z",
  "salt_b64": "...",
  "nonce_b64": "...",
  "ciphertext_b64": "..."
}
```

## Güvenlik Hususları

Bu araç **gerçek kriptografik algoritmalar** kullanır:

- **AES-256-GCM**: Endüstri standardı kimlik doğrulamalı şifreleme
- **Argon2id**: Password Hashing Competition kazananı, GPU/ASIC saldırılarına dirençli
- **Rastgele Nonce**: Her şifreleme için 12-byte kriptografik güvenli rastgele nonce
- **Rastgele Salt**: Her şifreleme için 16-byte kriptografik güvenli rastgele salt

**Ancak** güvenlik doğru kullanıma bağlıdır:

⚠️ **Güçlü, benzersiz şifreler kullanın** — zayıf şifreler sözlük saldırılarına karşı savunmasızdır  
⚠️ **Lock dosyalarınızı koruyun** — şifreli veriler hâlâ çevrimdışı saldırıya uğrayabilir  
⚠️ **Bu, üretim ortamları için uygun gizli bilgi yönetiminin (HashiCorp Vault, AWS Secrets Manager vb.) yerini almaz**  
⚠️ **Şifrelerinizi yedekleyin** — şifreyi kaybederseniz kurtarma mekanizması yoktur  

## Katkıda Bulunma

Katkılarınızı bekliyoruz! Pull Request göndermekten çekinmeyin.

```bash
# Testleri çalıştır
cargo test

# Clippy çalıştır
cargo clippy -- -D warnings

# Kodu formatla
cargo fmt
```

## Lisans

MIT License - Detaylar için [LICENSE](LICENSE) dosyasına bakın.
