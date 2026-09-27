//! v0.7.0 A4, second half: "a YubiKey-configured wallet refuses to open without it".
//!
//! Runs the wallet's own entry points (the same ones the Tauri layer calls) in a scratch
//! HOME, one step per invocation so the key can be removed and re-inserted between steps:
//!
//!   cargo build --release --example yubikey_refusal
//!   export HOME=<scratch home>; export PATH=$HOME/.cargo/bin:$PATH   (age-plugin-yubikey)
//!   yubikey_refusal probe                 what the plugin sees: recipients and identities on the key
//!   yubikey_refusal init <pin>            create a wallet sealed to the key (needs a key with an age identity)
//!   yubikey_refusal unlock <pin>          try to open it: Ok with the key, refused without it
//!   yubikey_refusal backup                backup, which must carry the YubiKey stub
//!   yubikey_refusal restore <backup.db>   restore, after which unlock must behave exactly as before
//!
//! The PIN is the wallet's unlock password in YubiKey mode. Nothing here is a secret of any
//! real wallet: the scratch HOME holds a fresh, empty, throwaway wallet.
use std::env;

fn guard_home() -> anyhow::Result<String> {
    let home = env::var("HOME")?;
    if home.contains("captain") || home.contains("user2") || home.contains("testA") || home.contains("testB")
        || !(home.contains("scratch") || home.contains("testC"))
    {
        anyhow::bail!("refusing: HOME must be a scratch or testC directory (got {home})");
    }
    Ok(home)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let home = guard_home()?;
    *zecboat_core::rpc::PROVIDER_URL.lock().unwrap() = "http://127.0.0.1:1".to_string(); // never talk to a node
    println!("wallet home: {home}");
    match args.get(1).map(String::as_str) {
        Some("probe") => {
            println!("plugin installed: {}", zecboat_core::yubi::plugin_installed());
            println!("recipients (age1yubikey1…): {:?}", zecboat_core::yubi::list_recipients()?);
            println!("identities  (AGE-PLUGIN-YUBIKEY-…): {}", zecboat_core::yubi::list_identities()?.len());
            println!("is_yubikey_connected: {}", zecboat_core::yubi::is_yubikey_connected());
        }
        Some("init") if args.len() == 3 => {
            // Birthday explicit so the node is never asked.
            let r = zecboat_core::initialize_new_wallet(args[2].clone(), true, Some(3_497_000)).await;
            match r {
                Ok(msg) => println!("init: OK — {}", msg.lines().next().unwrap_or("")),
                Err(e) => println!("init: FAILED — {e}"),
            }
            let stub = zecboat_core::paths::yubikey_stub_path()?;
            println!("stub present: {} ({})", stub.exists(), stub.display());
            println!("wallet_uses_yubikey: {:?}", zecboat_core::wallet_uses_yubikey().await);
        }
        Some("unlock") if args.len() == 3 => {
            // `@path` reads the PIN from a file the user wrote themselves (chmod 600), so the
            // PIN never appears on a command line, in a transcript or in shell history.
            let pin = if let Some(path) = args[2].strip_prefix('@') {
                std::fs::read_to_string(path)?.trim().to_string()
            } else {
                args[2].clone()
            };
            let t = std::time::Instant::now();
            match zecboat_core::unlock_wallet(pin, true).await {
                Ok(()) => println!("unlock: OPENED in {:.1?}", t.elapsed()),
                Err(e) => println!("unlock: REFUSED in {:.1?} — {e}", t.elapsed()),
            }
            zecboat_core::lock_wallet();
        }
        Some("backup") => match zecboat_core::backup_wallet().await {
            Ok(msg) => println!("backup: {msg}"),
            Err(e) => println!("backup: FAILED — {e}"),
        },
        Some("restore") if args.len() == 3 => match zecboat_core::restore_backup(args[2].clone()).await {
            Ok(msg) => println!("restore: {msg}"),
            Err(e) => println!("restore: FAILED — {e}"),
        },
        _ => anyhow::bail!("usage: yubikey_refusal probe | init <pin> | unlock <pin> | backup | restore <backup.db>"),
    }
    Ok(())
}
