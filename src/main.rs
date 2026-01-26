//! env-lock CLI: .env dosyalarını güvenle şifrele ve aç
//!
//! Kullanım:
//!   env-lock seal <input> [--out <output>] [--password <pw>] [--profile <name>] [--stdout] [--force]
//!   env-lock open <lock>  [--out <output>] [--password <pw>] [--profile <name>] [--stdout] [--force]
//!   env-lock status <lock>

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use env_lock_rs::{
    default_open_output, default_seal_output, file_exists, format_status, get_password,
    json_to_lock, lock_to_json, open, read_file_bytes, seal, write_file_bytes, Argon2Params,
};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "env-lock")]
#[command(author = "BeyazAdam")]
#[command(version = "0.1.0")]
#[command(about = "Seal and open .env files with AES-256-GCM encryption", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Seal (encrypt) a file into a .lock file
    Seal {
        /// Input file path to encrypt
        input_path: String,

        /// Output file path (default: <input>.lock)
        #[arg(short, long)]
        out: Option<String>,

        /// Encryption password (or use ENV_LOCK_KEY env var)
        #[arg(short, long)]
        password: Option<String>,

        /// Profile name to store in the lock file
        #[arg(long, default_value = "default")]
        profile: String,

        /// Output to stdout instead of file
        #[arg(long)]
        stdout: bool,

        /// Overwrite output file if it exists
        #[arg(short, long)]
        force: bool,
    },

    /// Open (decrypt) a .lock file
    Open {
        /// Lock file path to decrypt
        lock_path: String,

        /// Output file path (default: <lock>.out)
        #[arg(short, long)]
        out: Option<String>,

        /// Decryption password (or use ENV_LOCK_KEY env var)
        #[arg(short, long)]
        password: Option<String>,

        /// Expected profile name (will error if mismatch)
        #[arg(long)]
        profile: Option<String>,

        /// Output to stdout instead of file
        #[arg(long)]
        stdout: bool,

        /// Overwrite output file if it exists
        #[arg(short, long)]
        force: bool,
    },

    /// Show metadata of a lock file
    Status {
        /// Lock file path to inspect
        lock_path: String,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Hata: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Argon2 parametreleri (varsayılan değerler)
    // Güvenlik/performans dengesinde ayarlanabilir
    let params = Argon2Params::default();

    match cli.command {
        Commands::Seal {
            input_path,
            out,
            password,
            profile,
            stdout,
            force,
        } => cmd_seal(
            &input_path,
            out,
            password.as_deref(),
            &profile,
            stdout,
            force,
            &params,
        ),

        Commands::Open {
            lock_path,
            out,
            password,
            profile,
            stdout,
            force,
        } => cmd_open(
            &lock_path,
            out,
            password.as_deref(),
            profile.as_deref(),
            stdout,
            force,
            &params,
        ),

        Commands::Status { lock_path } => cmd_status(&lock_path),
    }
}

/// Seal komutu: dosyayı şifrele
fn cmd_seal(
    input_path: &str,
    out: Option<String>,
    password: Option<&str>,
    profile: &str,
    stdout: bool,
    force: bool,
    params: &Argon2Params,
) -> Result<()> {
    // Password al
    let password = get_password(password)?;

    // Input dosyasını oku
    let plaintext = read_file_bytes(input_path)?;

    // Şifrele
    let lock = seal(&plaintext, &password, profile, params)?;
    let json = lock_to_json(&lock)?;

    // Output
    if stdout {
        println!("{}", json);
    } else {
        let output_path = out.unwrap_or_else(|| default_seal_output(input_path));

        // Force kontrolü
        if !force && file_exists(&output_path) {
            bail!(
                "Dosya zaten mevcut: {}\nÜzerine yazmak için --force kullanın",
                output_path
            );
        }

        write_file_bytes(&output_path, json.as_bytes())?;
        eprintln!("✓ Sealed: {} -> {}", input_path, output_path);
    }

    Ok(())
}

/// Open komutu: şifreyi çöz
fn cmd_open(
    lock_path: &str,
    out: Option<String>,
    password: Option<&str>,
    expected_profile: Option<&str>,
    stdout: bool,
    force: bool,
    params: &Argon2Params,
) -> Result<()> {
    // Password al
    let password = get_password(password)?;

    // Lock dosyasını oku ve parse et
    let lock_data = read_file_bytes(lock_path)?;
    let lock_json = String::from_utf8(lock_data).context("Lock dosyası geçerli UTF-8 değil")?;
    let lock = json_to_lock(&lock_json)?;

    // Şifreyi çöz
    let plaintext = open(&lock, &password, expected_profile, params)?;

    // Output
    if stdout {
        io::stdout()
            .write_all(&plaintext)
            .context("stdout yazma hatası")?;
    } else {
        let output_path = out.unwrap_or_else(|| default_open_output(lock_path));

        // Force kontrolü
        if !force && file_exists(&output_path) {
            bail!(
                "Dosya zaten mevcut: {}\nÜzerine yazmak için --force kullanın",
                output_path
            );
        }

        write_file_bytes(&output_path, &plaintext)?;
        eprintln!("✓ Opened: {} -> {}", lock_path, output_path);
    }

    Ok(())
}

/// Status komutu: lock dosyası metadata'sını göster
fn cmd_status(lock_path: &str) -> Result<()> {
    let lock_data = read_file_bytes(lock_path)?;
    let lock_json = String::from_utf8(lock_data).context("Lock dosyası geçerli UTF-8 değil")?;
    let lock = json_to_lock(&lock_json)?;

    println!("{}", format_status(&lock));

    Ok(())
}
