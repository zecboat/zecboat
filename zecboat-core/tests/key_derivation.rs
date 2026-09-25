//! Key derivation: mnemonic → seed → `UnifiedSpendingKey` → UFVK → unified address.
//!
//! A wrong derivation does not error. It succeeds, derives a *different* wallet,
//! shows a zero balance, and is indistinguishable from "the funds are gone". So
//! these tests compare against constants that were checked outside this codebase,
//! and they drive the real entry points rather than a copy of their logic.
//!
//! The plan this file implements is `KEY_DERIVATION_TESTS.md` (T1–T4, T6–T9).
//!
//! # The fixtures, and how they were verified
//!
//! **Seeds.** Every seed here is a published BIP-39 test vector (the Trezor set
//! that the BIP itself links to). They are the most public seeds in existence,
//! which is precisely why they are safe to commit: nobody should ever hold funds
//! on them, and other tools publish what they derive to. Never replace them with
//! a seed that has held funds — this file lives in git forever.
//!
//! **BIP-39 seed bytes** (`SEED_VECTORS`) are the published vectors for the
//! `"TREZOR"` passphrase, and were recomputed independently of any Rust crate with
//! Python's `hashlib.pbkdf2_hmac`. The empty-passphrase seeds — the passphrase
//! Zecboat actually uses — were computed the same way:
//!
//! ```text
//! python3 -c 'import hashlib,sys; m=sys.argv[1]; p=sys.argv[2] if len(sys.argv)>2 else ""; \
//!   print(hashlib.pbkdf2_hmac("sha512", m.encode(), ("mnemonic"+p).encode(), 2048).hex())' \
//!   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
//! ```
//!
//! **UFVK and unified-address constants** (`KNOWN_WALLETS`) were generated ONCE by
//! this build (`print_fixtures`, below, `cargo test -- --ignored --nocapture`).
//! A constant produced by the code it tests only proves self-consistency, so each
//! leg was checked against something else before being committed:
//!
//! - *Transparent receiver*: the unified address's P2PKH receiver is asserted to
//!   equal a `t1…` address derived at `m/44'/133'/0'/0/<index>` by a pure-Python
//!   BIP-32/secp256k1 implementation that shares no code with this crate
//!   (`tests/fixtures/verify_transparent_leg.py`).
//! - *Sapling and Orchard receivers*: no implementation outside the `librustzcash`
//!   lineage exists in this environment, so the check was against a DIFFERENT
//!   generation of it. Every constant in `KNOWN_WALLETS` (UFVK, default address
//!   and its index, account 1, testnet) was re-derived from the Python-computed
//!   seed bytes — bip0039 out of the loop — by a scratch crate pinned to
//!   `zcash_keys 0.6.1` (December 2024) with `orchard 0.10.2`, `sapling-crypto
//!   0.4.0`, `zip32 0.1.3`, `zcash_transparent 0.1.0`, `zcash_protocol 0.4.3`:
//!   a different major line of every crate involved, released a year and a half
//!   before the versions this wallet builds against. All ten values agreed byte
//!   for byte. (Those releases pull in yanked crates and no longer build cleanly;
//!   they were fetched from the static crates.io archive and patched in by path.)
//!   For a check that shares no lineage at all, restore `abandon … art` into
//!   Zingo CLI or Zingo PC and compare `exportufvk` and the first address with
//!   `KNOWN_WALLETS[0]`.
//!
//! If a crate upgrade ever changes one of these constants, that upgrade has
//! changed which wallet a seed opens. Do not update the constant. Find out why.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bip0039::{English, Mnemonic};
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::{MainNetwork, TestNetwork};
use zcash_transparent::keys::{IncomingViewingKey, NonHardenedChildIndex};
use zip32::AccountId;

// ─── Fixtures ────────────────────────────────────────────────────────────────

/// Published BIP-39 English vectors, passphrase `"TREZOR"`. Entropy → phrase → seed.
const SEED_VECTORS: &[(&str, &str, &str)] = &[
    (
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    ),
    (
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
    ),
    (
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
    ),
    (
        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
    ),
];

/// The same phrases with the EMPTY passphrase, which is what every Zecboat call
/// site passes to `to_seed`. Computed with Python `hashlib` (see the module docs).
const EMPTY_PASSPHRASE_SEEDS: &[(&str, &str)] = &[
    (
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    ),
    (
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096",
    ),
    (
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "b6a6d8921942dd9806607ebc2750416b289adea669198769f2e15ed926c3aa92bf88ece232317b4ea463e84b0fcd3b53577812ee449ccc448eb45e6f544e25b6",
    ),
    (
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840",
    ),
    (
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "e28a37058c7f5112ec9e16a3437cf363a2572d70b6ceb3b6965447623d620f14d06bb321a26b33ec15fcd84a3b5ddfd5520e230c924c87aaa0d559749e044fef",
    ),
];

/// The 24-word phrase the wallet fixtures are built on. 24 words, like the wizard
/// generates. Entropy is 32 zero bytes: the best-known throwaway seed there is.
const PHRASE_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// A second throwaway phrase, used where two different wallets are needed.
const PHRASE_24_ALT: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";

/// What a seed derives to, on mainnet, with the parameters every call site uses
/// (empty passphrase, `AccountId::ZERO`). Generated by `print_fixtures`; see the
/// module docs for how each leg was verified before being committed.
struct KnownWallet {
    phrase: &'static str,
    /// `UnifiedSpendingKey::from_seed(MainNetwork, seed, ZERO).to_unified_full_viewing_key().encode(MainNetwork)`
    ufvk: &'static str,
    /// `ufvk.default_address(UnifiedAddressRequest::AllAvailableKeys)` — the request
    /// `zcash_client_sqlite` uses when it creates the account, so this is the first
    /// row of the `addresses` table, i.e. what the user is shown.
    default_ua: &'static str,
    /// The diversifier index at which that default address was found.
    default_ua_index: u32,
    /// The P2PKH receiver inside `default_ua`, as a `t1…` address. Independently
    /// verifiable: BIP-44 path `m/44'/133'/0'/0/<default_ua_index>`.
    default_ua_transparent: &'static str,
    /// Account 1 from the same seed. Must differ from `ufvk` (T8).
    account_1_ufvk: &'static str,
    /// The same seed on `TestNetwork`, encoded with the MAINNET HRP so the
    /// comparison is on key material, not on the human-readable prefix (T9).
    testnet_ufvk_as_main_hrp: &'static str,
}

const KNOWN_WALLETS: &[KnownWallet] = &[
    KnownWallet {
        phrase: PHRASE_24,
        ufvk: "uview1wj07tp4y3rwzjplg68c3lum2avq4v3j0w0mf0urdlxzthnfr26q8ssz9hvylspj638tuh2r233gaxm2qh27gj6m9q25prk7gt8xwqzmwxm580tg0f5llvr7d6h4y6jc2t7zl7lz9ge60ta6226jyysgk8xpu2wqxesrw4q2mydrhj5dea5l9scl0p3l4ayqgfej54wex5aa2ylq89nyqg94l4lh6dawuc2e3s8v7737zn7p5fl96hhpjqg4jucnp2r2jjqxev3z7lp3k9ulfpl2gw0lng8vfe8hj8afggqzdwxgfaq6dy82guvh34kv4q5ay7gq6n0ujg7exu0mgznpr4wf0agjdhnd4k6af5md3f3msqedw364vx3lyd3hwekvrulywa4c0ja4ze2fxtcm0vrz0278g9n37y0jg6dx847g3peyq9lwmm04ac3tt4sldnrcfc5ew3k0aqgycnryfvv44zxzng485ks27wky2ulfy9q8hu97l",
        default_ua: "u16sw4v6wy7f4jzdny55yzl020tp3yqg3c85dc6n7mmq0urfm6adqg79hxmyk85ufn4lun4pfh5q48cc3kvxhxm3w978eqqecdd260gkzjrkun6z7m9mcrt2zszaj0mvk6ufux2zteqwh57cq906hz3rkg63duaeqsvjelv9h5srct0zq8rvlv23wz5hed7zuatqd7p6p4ztugc4t4w2g",
        default_ua_index: 0,
        default_ua_transparent: "t1dUDJ62ANtmebE8drFg7g2MWYwXHQ6Xu3F",
        account_1_ufvk: "uview1fzmv506uqhq5ktmj9ldyf7ww00avknney4zpdh73n9suwjhx9je7tswv93e4uxmeunn23cqc2wg0e3l4eqvq0qhheh0hdzznmp4pwlmp9mfa3klm3a28d436anavapwecctk3ul4qqcaankh0lgk5jz9jl4t82p4j03505h92k92d5t23y6rmktp9z0dc7a0v0dzjgl2qtdcrq4z6kmf6xy78xqwqxq27v39r2d3tpwfpzkdjccenxsee7vlv8t533p4y3pckf6xzcq7e226nev4yuevvtfsrxgj0lxxzt9x8949jwn8kdwyslzyjcugk8f2akux3rjgwprtwxpcux26nk8ujk2llrjpg77l2mj9ac6lmva2zeawzwtyrtsmdgrs75snd2exdge33kll6dj4spp6wvrfczjnkrqugy8qm4y238nt850ezpmsse9z0w4rs2klj0hydnkxssasc3cndrvzr55l8u6mfyhm9peg0v8htg4j39u4",
        testnet_ufvk_as_main_hrp: "uview1f9ppkzgc2utk6k734vxerwwc3alj7p6j79kf5ee30a35xkn6ds22wwwqvf0t33enchvgtg00rvtqwxsz5zc4cdhk6hkhxn0ltxfdz7mqxt9ap88fpdrryys4v05qvqytdpy5qddj3a32zed6udt3lv08mhhq6705pg3up2jv93vgjwpva32h0g05fvyn89y76d9tlj3uvxlehh925ggyz6nxhkgtywvrgqp665xyc7azk8ey8lsan7ndnjvcrkl506w8gf4pgw0xmd4yl86nquph6n7r3fp8w8h0nj8uj4wf9z2p2h6f3wuqwjcp2cmar6zar949x76dnhu4kdpz7qg50cw3wdh4sg28jzgsqqcspfdvc80zzv99xck70cu0uqnuautlfa5wp2uz2m6u8z2egapg8eedqhw89ccunt5sgvkljwrzcnt780z0sywc8tau8y7u4mky0tpmkr00ug6xluxzpa5pqlexnkx4je4mqughf5lrzurx",
    },
    KnownWallet {
        phrase: PHRASE_24_ALT,
        ufvk: "uview1dayljrzcf0qyfcn2dan5xag28dyvclska4muqq56fcz2sshjshppavh6eul8lc88nexh3yjl3jcx80a5803lm84a7d0nrw8u5lcku6yje7a4kj9y7rhtz30pjwna83nt8m4ldlz6r7sg5ny2lshjlklpsta7sdk8y9z5mupc65qn38hslcvkk3l0k7490e5jujtmeg9rzdfdwq2z3qdzs302t3rah40s8ccel3y2te9gnx8342mfr0kzkcv6lh2cllt83m4l9dffqmwc8jvq82hnur0gxzh45jql78upjp8p2assaru3e6gsl47feyk2w2ka28q8u786wx4d9gzlx24dp2ud5wa8e5evw7ala65k4znm47akyc0http7xe0fyt8kex7w3ge63l54mdp0f3hy73xu7zsgpvkjzdwgmez2xcygdpez3n5nzla60hs7dqc675y0wef3svug2lq83q2k7jj0lye8z2txayt4efw3z3q6qgdyegca",
        default_ua: "u1cqln60wgrtd8a4yyz0u6dmzlqjj56ajug88l7yg4dqpnjm0plp5pmw7kyfgjgwf2u43n27qpds3deeu2gjmvx4yxqzjc77pfe0vskt5ge4ncwc3dwm44pv9a79h48avzertgsszrchwlm7k8kzrnz4cs8c9urcncy3qkjgdndtgj5jztxtzqmxv38nm3vzr8e29e8sjpeyx7q4c777f",
        default_ua_index: 2,
        default_ua_transparent: "t1Pece6MDgh5ohN49EJpNBskszKiaQEReFF",
        account_1_ufvk: "uview13g8plttxnd6hjqmv94lgemltsgxt3mkwr0q7v70zgnwz4fr8zqqph9cmdqkkxhtw6t02nu90cqzhcg5ye7gmvu7kcmqkslqt6dr40t9rn7xm3l3u2gl0mhsa67mt8sx25lguzc6tl36y33plfq9acmhhww8yrzmy4pknhmmk64yatmt3cnrm64thpr8j8xflgqmqplhzlhjq9ckvqp84zmmtfptfe62grv3wdzj0h5tza5zchv8rjy7hpfupxhakrxtpdlhrfntlqeckefkhclstfut4vhu97uw8h0wstw3ayx60y4z5cj0d9cknm4qkwavfh5lm2vqu6f9a4yapdym3dtrnrr8yu3w8ct2ewnvqevkcgsxqla6nfhdz9ns3rfaeyv0p2wg0hvd9zr53ktz8lxh6w3j4lxph6hf92lv3z3qu0lrec3mze2jux7f5mysqvm54c53hdsmqkmdzrknmkcffwx553kpraz4sga763c0x8gkgs3z4",
        testnet_ufvk_as_main_hrp: "uview1q0jyr2dgfvjya2h3qxalsgvspgkd9w20jeuvedx5h3h2vfydgces8gy4dkcukew0f06jg53pd2dfxuts2dr0cj8f9g922dmey875n4vxyx5ahdc0klhq78hd4w9ek0k2v56s0yrc3eq6txmc0h8c7vhpks28e0whkc2sqkprq2w9nkd5vn003lq44j0stt4wzmjdqfy7789yw9jfwupmc75azml7s0gqnvvj9fuknrf9d20zwuf6u3l5d99yxmmhc0v97lcd9cpsq89wceh9qgmc8gtmthx43mejjufsr822vrxsk9ekpwqvtgw4n8z2vm8lduth4tcn4tnk66g7sdnuf8r5mhyjm39cp26m098sf7egl34smkclsglymk9jz6l9q0smvfhpv2c2hgdf3enhf2ymgmj8mepf90anxa4g5uwxfzrk75t0qvpguzv63gtk9cmafjyvgv47z9t9gxm8s8nchvxl52xngexu5an5ryp86594dwcj",
    },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Exactly what every call site does. If this helper and the call sites ever
/// disagree, `every_source_call_site_uses_the_same_parameters` is meant to notice.
fn derive_usk<P: zcash_protocol::consensus::Parameters>(
    params: &P,
    phrase: &str,
    account: AccountId,
) -> UnifiedSpendingKey {
    let mnemonic = Mnemonic::<English>::from_phrase(phrase).expect("fixture phrase is valid");
    let seed = mnemonic.to_seed("");
    UnifiedSpendingKey::from_seed(params, &seed, account).expect("derivation from a 64-byte seed")
}

fn mainnet_ufvk(phrase: &str) -> UnifiedFullViewingKey {
    derive_usk(&MainNetwork, phrase, AccountId::ZERO).to_unified_full_viewing_key()
}

fn default_ua(ufvk: &UnifiedFullViewingKey) -> (UnifiedAddress, u32) {
    let (ua, idx) = ufvk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .expect("a default address exists");
    let idx: u128 = idx.into();
    (ua, u32::try_from(idx).expect("diversifier index fits in u32"))
}

fn transparent_receiver_of(ua: &UnifiedAddress) -> String {
    let t = ua.transparent().expect("the default UA carries a transparent receiver");
    Address::from(*t).encode(&MainNetwork)
}

/// `HOME` and the process-wide `WALLET_PASSWORD` / `PROVIDER_URL` are global, and
/// cargo runs tests on parallel threads. Every test that touches them holds this.
static ENV: Mutex<()> = Mutex::new(());

/// A throwaway `HOME`. Restores the real one on drop, and refuses to run if the
/// scratch directory is anywhere under the real home — every wallet path derives
/// from `HOME`, so this is the only thing standing between the test and a real wallet.
struct Sandbox {
    home: PathBuf,
    real_home: Option<String>,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let real_home = std::env::var("HOME").ok();
        let home = std::env::temp_dir().join(format!("zb-keytest-{}-{}", std::process::id(), tag));
        if let Some(rh) = &real_home {
            assert!(!rh.is_empty() && !home.starts_with(rh), "scratch HOME must not be under the real HOME");
        }
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        // `recover_wallet_from_seed` asks the node for the chain tip. A closed loopback
        // port fails immediately; the default provider would hang on a cold network.
        *zecboat_core::rpc::PROVIDER_URL.lock().unwrap() = "http://127.0.0.1:1".to_string();
        Sandbox { home, real_home }
    }

    fn wallet_db(&self) -> PathBuf {
        self.home.join(".AppVault/data/wallet.db")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        match &self.real_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        *zecboat_core::rpc::WALLET_PASSWORD.lock().unwrap() = None;
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// The UFVK `zcash_client_sqlite` stored when it created the account, and the
/// first address it derived. This is the wallet the user actually gets.
fn stored_account(db: &Path) -> (String, String) {
    let conn = rusqlite::Connection::open_with_flags(
        db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open wallet.db");
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 1, "expected exactly one account in a fresh wallet");
    let ufvk: String = conn.query_row("SELECT ufvk FROM accounts", [], |r| r.get(0)).unwrap();
    let addr: String = conn
        .query_row("SELECT address FROM addresses ORDER BY id LIMIT 1", [], |r| r.get(0))
        .unwrap();
    (ufvk, addr)
}

// ─── T1: BIP-39 phrase → seed ────────────────────────────────────────────────

#[test]
fn bip39_published_vectors_with_trezor_passphrase() {
    for (entropy_hex, phrase, seed_hex) in SEED_VECTORS {
        let from_phrase = Mnemonic::<English>::from_phrase(*phrase).unwrap();
        let from_entropy = Mnemonic::<English>::from_entropy(hex::decode(entropy_hex).unwrap()).unwrap();
        assert_eq!(from_entropy.phrase(), *phrase, "entropy → phrase");
        assert_eq!(hex::encode(from_phrase.to_seed("TREZOR")), *seed_hex, "phrase → seed: {phrase}");
    }
}

/// Locks the empty passphrase. Changing `to_seed("")` to `to_seed(&password)`
/// would change every address in every wallet, silently.
#[test]
fn bip39_vectors_with_the_empty_passphrase_the_wallet_uses() {
    for (phrase, seed_hex) in EMPTY_PASSPHRASE_SEEDS {
        let m = Mnemonic::<English>::from_phrase(*phrase).unwrap();
        assert_eq!(hex::encode(m.to_seed("")), *seed_hex, "{phrase}");
        assert_ne!(hex::encode(m.to_seed("TREZOR")), *seed_hex, "passphrase must matter");
    }
}

// ─── T2 / T3: seed → UFVK / default UA are stable ────────────────────────────

#[test]
fn seed_to_ufvk_is_stable() {
    for w in KNOWN_WALLETS {
        let ufvk = mainnet_ufvk(w.phrase);
        assert_eq!(ufvk.encode(&MainNetwork), w.ufvk, "UFVK changed for `{}…`", &w.phrase[..16]);
        // The encoding round-trips, so the constant is a real key and not a typo.
        UnifiedFullViewingKey::decode(&MainNetwork, w.ufvk).expect("fixture UFVK decodes");
    }
}

#[test]
fn seed_to_default_unified_address_is_stable() {
    for w in KNOWN_WALLETS {
        let ufvk = mainnet_ufvk(w.phrase);
        let (ua, idx) = default_ua(&ufvk);
        assert_eq!(ua.encode(&MainNetwork), w.default_ua);
        assert_eq!(idx, w.default_ua_index);
        assert!(ua.orchard().is_some(), "default UA has an Orchard receiver");
        assert!(ua.sapling().is_some(), "default UA has a Sapling receiver");
        assert_eq!(transparent_receiver_of(&ua), w.default_ua_transparent);

        // The transparent receiver is at BIP-44 m/44'/133'/0'/0/<idx> — the leg that
        // `tests/fixtures/verify_transparent_leg.py` reproduces without this crate.
        let tivk = ufvk.transparent().unwrap().derive_external_ivk().unwrap();
        let t = tivk.derive_address(NonHardenedChildIndex::from_index(idx).unwrap()).unwrap();
        assert_eq!(Address::from(t).encode(&MainNetwork), w.default_ua_transparent);
    }
}

// ─── T4: every entry point derives the same key ──────────────────────────────

/// Drives the three database-backed entry points a test can reach without a
/// synced chain: `initialize_new_wallet`, `recover_wallet_from_seed`,
/// `import_wallet` — each of which hands the seed to `create_account`, which
/// derives internally — plus `get_viewkey`, which derives by hand. All must
/// agree with each other and with the fixture.
///
/// Not drivable here, and covered only by the source scan below: the two
/// `send_transaction` sites and `batch_send_transaction` in `wallet.rs` (need
/// spendable notes), and `shield_transparent` in `rpc.rs` (needs the prover
/// parameters and a node).
#[tokio::test]
async fn database_backed_entry_points_agree_with_direct_derivation() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    const BIRTHDAY: u32 = 3_400_000; // explicit, so initialize_new_wallet needs no node

    // initialize_new_wallet: a fresh random phrase. The stored key must be what a
    // direct derivation of the returned phrase gives.
    {
        let sb = Sandbox::new("init");
        let phrase = zecboat_core::initialize_new_wallet("pw-one".into(), false, Some(BIRTHDAY))
            .await
            .expect("initialize_new_wallet");
        assert_eq!(phrase.split_whitespace().count(), 24);
        let expected = mainnet_ufvk(&phrase);
        let (stored_ufvk, stored_addr) = stored_account(&sb.wallet_db());
        assert_eq!(stored_ufvk, expected.encode(&MainNetwork), "create_account derived a different key");
        assert_eq!(stored_addr, default_ua(&expected).0.encode(&MainNetwork));
        let viewkey = zecboat_core::get_viewkey().await.expect("get_viewkey");
        assert_eq!(viewkey, stored_ufvk, "get_viewkey disagrees with the stored account");
    }

    // recover_wallet_from_seed: the fixture phrase, into an empty HOME, must give
    // exactly the fixture wallet.
    let w = &KNOWN_WALLETS[0];
    let sb = Sandbox::new("recover");
    zecboat_core::recover_wallet_from_seed(w.phrase, "pw-two".into(), Some(BIRTHDAY))
        .await
        .expect("recover_wallet_from_seed");
    let (stored_ufvk, stored_addr) = stored_account(&sb.wallet_db());
    assert_eq!(stored_ufvk, w.ufvk, "recovery derived a different wallet from the fixture phrase");
    assert_eq!(stored_addr, w.default_ua);
    assert_eq!(zecboat_core::get_viewkey().await.unwrap(), w.ufvk);

    // import_wallet: replaces the wallet in the SAME home (it needs the unlocked
    // identity recovery just wrote). Padded with whitespace on purpose: it stores
    // the string as given, and every reader must still find the same wallet.
    let alt = &KNOWN_WALLETS[1];
    let padded = format!("  {}\n", alt.phrase);
    zecboat_core::import_wallet(&padded, Some(BIRTHDAY)).await.expect("import_wallet");
    let (stored_ufvk, stored_addr) = stored_account(&sb.wallet_db());
    assert_eq!(stored_ufvk, alt.ufvk, "import derived a different wallet from the fixture phrase");
    assert_eq!(stored_addr, alt.default_ua);
    assert_eq!(zecboat_core::get_viewkey().await.unwrap(), alt.ufvk);
}

/// The four sites a test cannot drive are held to the same parameters by reading
/// the source. Crude, deliberately: a new derivation site, or one that changes its
/// passphrase, network, or account, must come here and explain itself.
#[test]
fn every_source_call_site_uses_the_same_parameters() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut to_seed_sites = Vec::new();
    let mut from_seed_sites = Vec::new();

    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        // `src/bin.rs` is not a cargo target (no `[[bin]]`, and not at `src/main.rs`
        // or `src/bin/*.rs`), calls APIs that no longer exist, and derives from a
        // 32-zero-byte seed. It is dead code that only this scan can see. Flagged
        // in the review that added this file; skip it until it is deleted.
        if path.file_name().and_then(|n| n.to_str()) == Some("bin.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();

        for (i, line) in text.lines().enumerate() {
            if let Some(pos) = line.find(".to_seed(") {
                let arg = call_text(line, pos + ".to_seed".len());
                to_seed_sites.push((format!("{name}:{}", i + 1), arg));
            }
        }
        let mut from = 0;
        while let Some(pos) = text[from..].find("UnifiedSpendingKey::from_seed(") {
            let start = from + pos + "UnifiedSpendingKey::from_seed".len();
            let line_no = text[..start].lines().count();
            from_seed_sites.push((format!("{name}:{line_no}"), call_text(&text, start)));
            from = start;
        }
    }

    for (site, args) in &to_seed_sites {
        assert_eq!(args.trim(), "(\"\")", "{site}: to_seed must use the empty passphrase, got {args}");
    }
    for (site, args) in &from_seed_sites {
        assert!(args.contains("MainNetwork"), "{site}: from_seed must derive for MainNetwork: {args}");
        assert!(
            args.contains("AccountId::ZERO") || args.contains("AccountId::try_from(0)"),
            "{site}: from_seed must derive account 0: {args}"
        );
    }

    // The counts are the drift alarm. If either changes, a derivation site was added
    // or removed: read it, then update the number here.
    //
    // 8 -> 9 on 2026-09-24. The new site is `seed_fingerprint()` in rpc.rs, which derives
    // the seed only to compute its ZIP-32 fingerprint — it produces no spending key. It was
    // read before this number was changed, which is the whole point of the alarm: the
    // assertions above still hold for it, since it passes the empty passphrase like every
    // other site. One more `to_seed`, no more ways to derive a key.
    //
    // 9 -> 7 and 5 -> 3 on 2026-09-25 (R7). wallet.rs held three copies of the spend-path
    // derivation — batch, ordinary and asset sends. They collapsed into one function,
    // `wallet::spending_key_from_phrase`, which is now the only place a spending key is
    // derived for signing. Two fewer sites, no fewer ways to derive a key: the three
    // callers still derive, through the one function. Read before the numbers changed.
    assert_eq!(to_seed_sites.len(), 7, "to_seed sites: {to_seed_sites:?}");
    assert_eq!(from_seed_sites.len(), 3, "from_seed sites: {from_seed_sites:?}");
}

/// The text of a call's argument list, from the `(` at `open` to its matching `)`.
fn call_text(text: &str, open: usize) -> String {
    let bytes = text.as_bytes();
    assert_eq!(bytes[open], b'(', "expected '(' at {open}");
    let mut depth = 0usize;
    for (i, b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return text[open..=i].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced parentheses after {open}");
}

// ─── T6 / T7: invalid phrases are rejected and not echoed ────────────────────

fn twenty_four(word: &str) -> String {
    std::iter::repeat(word).take(24).collect::<Vec<_>>().join(" ")
}

#[test]
fn invalid_phrases_are_rejected_not_coerced() {
    let words: Vec<&str> = PHRASE_24.split(' ').collect();

    let bad_checksum = twenty_four("abandon"); // 24 × abandon: checksum fails
    let twenty_three = words[..23].join(" ");
    let twenty_five = format!("{PHRASE_24} abandon");
    let eleven = words[..11].join(" ");
    let unknown_word = PHRASE_24.replacen("art", "zecboat", 1);
    let uppercase = PHRASE_24.to_uppercase();
    let spanish = PHRASE_24.replacen("abandon", "ábaco", 1);
    let cases: &[(&str, &str)] = &[
        ("bad checksum", &bad_checksum),
        ("23 words", &twenty_three),
        ("25 words", &twenty_five),
        ("11 words", &eleven),
        ("unknown word", &unknown_word),
        ("uppercase", &uppercase),
        ("wrong language", &spanish),
        ("empty", ""),
        ("whitespace only", "   \n\t "),
        ("hex, not words", "408b285c123836004f4b8842c89324c1"),
    ];
    for (what, phrase) in cases {
        assert!(Mnemonic::<English>::from_phrase(*phrase).is_err(), "{what} was accepted: {phrase:?}");
    }
}

/// Whitespace and Unicode form are normalised by BIP-39, so these variants must
/// open the SAME wallet — a variant that silently opened a different one would be
/// the worst outcome here.
#[test]
fn equivalent_spellings_open_the_same_wallet() {
    let canonical = mainnet_ufvk(PHRASE_24).encode(&MainNetwork);
    let double_spaced = PHRASE_24.replace(' ', "  ");
    let padded = format!(" \t{PHRASE_24}\n");
    let newlines = PHRASE_24.replace(' ', "\n");
    for (what, phrase) in [
        ("double spaced", double_spaced),
        ("padded", padded),
        ("newline separated", newlines),
    ] {
        let m = Mnemonic::<English>::from_phrase(phrase.as_str())
            .unwrap_or_else(|e| panic!("{what} rejected: {e:?}"));
        assert_eq!(m.phrase(), PHRASE_24, "{what}: normalised phrase differs");
        assert_eq!(mainnet_ufvk(&phrase).encode(&MainNetwork), canonical, "{what}: different wallet");
    }
}

/// KNOWN ISSUE in `bip0039 0.12`: a phrase containing non-NFKD characters passes
/// validation (the checksum is computed on the NFKD form) but is STORED as typed,
/// and `to_seed` runs PBKDF2 over the stored text. BIP-39 requires NFKD before
/// PBKDF2, and the reference implementation does it, so such a phrase opens a
/// wallet that no other BIP-39 wallet would open. Fullwidth letters are the
/// clearest demonstration; the realistic route is a phrase copied out of a PDF
/// whose renderer substituted ligatures — "ﬁ" in `fine`/`first`/`fish`/`fit`,
/// "ﬂ" in `flag`/`flat`/`flee`, "ﬀ" in `effort` — which NFKD folds and this
/// crate does not.
///
/// This test pins the CURRENT behaviour so the hazard stays visible. When it
/// fails, the crate has been fixed (or the wallet normalises before parsing):
/// change the second assertion to equality and move the case into
/// `equivalent_spellings_open_the_same_wallet`.
#[test]
fn known_issue_non_nfkd_phrase_is_accepted_but_opens_a_different_wallet() {
    let fullwidth = PHRASE_24.replacen("art", "\u{ff41}\u{ff52}\u{ff54}", 1);
    let m = Mnemonic::<English>::from_phrase(fullwidth.as_str())
        .expect("accepted: validation normalises to NFKD");
    let canonical = Mnemonic::<English>::from_phrase(PHRASE_24).unwrap();
    assert_ne!(
        hex::encode(m.to_seed("")),
        hex::encode(canonical.to_seed("")),
        "bip0039 now normalises before PBKDF2 — flip this test to equality"
    );
}

/// The public entry points reject a bad phrase before touching disk, and their
/// error text does not carry any word of it. Seed words in an error string reach
/// logs, toasts and bug reports.
#[tokio::test]
async fn public_entry_points_reject_bad_phrases_without_echoing_them() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("reject");

    let bad = PHRASE_24.replacen("art", "zecboat", 1);
    let err = zecboat_core::recover_wallet_from_seed(&bad, "pw".into(), Some(3_400_000))
        .await
        .expect_err("recover must reject an unknown word");
    let text = format!("{err:?}");
    assert!(!text.contains("zecboat") && !text.contains("abandon"), "seed words in error: {text}");
    assert!(!sb.wallet_db().exists(), "recovery must not create a wallet from a bad phrase");

    // import_wallet validates the phrase before it even checks the lock state.
    let err = zecboat_core::import_wallet(&bad, None).await.expect_err("import must reject an unknown word");
    let text = format!("{err:?}");
    assert!(!text.contains("zecboat") && !text.contains("abandon"), "seed words in error: {text}");
    assert!(!sb.wallet_db().exists());
}

// ─── T8 / T9: account and network separation ─────────────────────────────────

#[test]
fn accounts_are_separated_and_stable() {
    for w in KNOWN_WALLETS {
        let a0 = derive_usk(&MainNetwork, w.phrase, AccountId::ZERO).to_unified_full_viewing_key();
        let a1 = derive_usk(&MainNetwork, w.phrase, AccountId::try_from(1).unwrap())
            .to_unified_full_viewing_key();
        assert_ne!(a0.encode(&MainNetwork), a1.encode(&MainNetwork), "account 0 and 1 collide");
        assert_ne!(default_ua(&a0).0.encode(&MainNetwork), default_ua(&a1).0.encode(&MainNetwork));
        assert_eq!(a1.encode(&MainNetwork), w.account_1_ufvk, "account 1 derivation changed");
        // Deterministic: a second derivation of account 0 is byte-identical.
        assert_eq!(a0.encode(&MainNetwork), mainnet_ufvk(w.phrase).encode(&MainNetwork));
    }
}

#[test]
fn networks_are_separated() {
    for w in KNOWN_WALLETS {
        let main = derive_usk(&MainNetwork, w.phrase, AccountId::ZERO).to_unified_full_viewing_key();
        let test = derive_usk(&TestNetwork, w.phrase, AccountId::ZERO).to_unified_full_viewing_key();
        // Both encoded with the mainnet prefix: the comparison is on the key material.
        // Coin type 133 vs 1 sits in every ZIP 32 path, so all three components differ.
        assert_ne!(main.encode(&MainNetwork), test.encode(&MainNetwork), "network does not affect derivation");
        assert_eq!(test.encode(&MainNetwork), w.testnet_ufvk_as_main_hrp, "testnet derivation changed");
        assert!(test.encode(&TestNetwork).starts_with("uviewtest"));
        assert!(main.encode(&MainNetwork).starts_with("uview"));
    }
}

// ─── Fixture generation ──────────────────────────────────────────────────────

/// Prints the `KnownWallet` values for the fixture phrases from the CURRENT build.
///
/// `cargo test --test key_derivation print_fixtures -- --ignored --nocapture`
///
/// Regenerate only to ADD a phrase. If an existing constant changes, the build has
/// changed which wallet a seed opens; that is a bug to chase, not a fixture to update.
#[test]
#[ignore]
fn print_fixtures() {
    for phrase in [PHRASE_24, PHRASE_24_ALT] {
        let ufvk = mainnet_ufvk(phrase);
        let (ua, idx) = default_ua(&ufvk);
        let a1 = derive_usk(&MainNetwork, phrase, AccountId::try_from(1).unwrap())
            .to_unified_full_viewing_key();
        let test = derive_usk(&TestNetwork, phrase, AccountId::ZERO).to_unified_full_viewing_key();
        println!("phrase: {phrase}");
        println!("  ufvk: {}", ufvk.encode(&MainNetwork));
        println!("  default_ua: {}", ua.encode(&MainNetwork));
        println!("  default_ua_index: {idx}");
        println!("  default_ua_transparent: {}", transparent_receiver_of(&ua));
        println!("  account_1_ufvk: {}", a1.encode(&MainNetwork));
        println!("  testnet_ufvk_as_main_hrp: {}", test.encode(&MainNetwork));
    }
}

// ─── F1t: the test the NFKD fix was owed ─────────────────────────────────────

/// A phrase carrying compatibility characters must open the SAME wallet.
///
/// `known_issue_non_nfkd_phrase_is_accepted_but_opens_a_different_wallet` above pins the
/// defect in `bip0039 0.12` — it calls `Mnemonic::from_phrase` DIRECTLY, so it describes
/// the crate and can never say anything about Zecboat. The fix in `742ca6d` normalises at
/// our own entry points instead, and that commit went in saying plainly that no test
/// exercised it. This is that test.
///
/// **Why it matters.** BIP-39 requires NFKD before PBKDF2. The crate normalises for the
/// checksum and then hashes the phrase as typed, so a contaminated phrase validates and
/// derives a seed no other BIP-39 wallet derives — silently, with no error, into an empty
/// wallet. The realistic route is a phrase copied out of a PDF whose renderer substituted
/// ligatures; the affected words are ordinary (*fine finger finish fire firm first fish
/// fit fix flag flame flash flat flavor flee effort*).
///
/// Fullwidth Latin is used rather than a ligature because it contaminates the fixture
/// phrase without changing which words it contains: NFKD folds `ａｒｔ` onto `art` exactly
/// as it folds `ﬁne` onto `fine`, and `abandon ×23 art` is a published vector.
#[tokio::test]
async fn a_non_nfkd_phrase_opens_the_same_wallet_through_our_entry_points() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    // Explicit, so nothing asks a node for the chain tip. Matches the constant used by
    // database_backed_entry_points_agree_with_direct_derivation, which is function-scoped.
    const BIRTHDAY: u32 = 3_400_000;
    let w = &KNOWN_WALLETS[0];

    // U+FF41 U+FF52 U+FF54 — fullwidth a, r, t.
    let contaminated = w.phrase.replacen("art", "\u{ff41}\u{ff52}\u{ff54}", 1);
    assert_ne!(contaminated, w.phrase, "the fixture must actually be contaminated");

    // recover_wallet_from_seed — the path someone uses when they have lost everything else.
    {
        let sb = Sandbox::new("nfkd-recover");
        zecboat_core::recover_wallet_from_seed(&contaminated, "pw".into(), Some(BIRTHDAY))
            .await
            .expect("a phrase that passes the checksum must be accepted");
        let (ufvk, _addr) = stored_account(&sb.wallet_db());
        assert_eq!(
            ufvk, w.ufvk,
            "recover_wallet_from_seed derived a DIFFERENT wallet from a phrase that differs \
             only by compatibility characters — the user would see an empty wallet and no error"
        );
    }

    // import_wallet — same phrase, same requirement, a different call site that had its own
    // copy of the parsing.
    {
        let sb = Sandbox::new("nfkd-import");
        zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
            .await
            .expect("a wallet must exist before importing into it");
        zecboat_core::unlock_wallet("pw".into(), false)
            .await
            .expect("unlock");
        zecboat_core::import_wallet(&contaminated, Some(BIRTHDAY))
            .await
            .expect("import must accept the contaminated phrase");
        let (ufvk, _addr) = stored_account(&sb.wallet_db());
        assert_eq!(
            ufvk, w.ufvk,
            "import_wallet derived a different wallet from the same phrase"
        );
    }
}

/// F6. Deriving the right wallet from a contaminated phrase is half of it; the wallet also
/// STORES the phrase, and hands it back through Settings → export. Storing the raw input
/// means the export shows fullwidth or ligature characters the user never typed on purpose
/// and, worse, a phrase that is not the one `recover_wallet_from_seed` would have stored
/// for the same seed. Both entry points must keep the normalised phrase.
#[tokio::test]
async fn an_imported_phrase_is_stored_normalised_not_as_typed() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    const BIRTHDAY: u32 = 3_400_000;
    let w = &KNOWN_WALLETS[0];
    // Fullwidth a-r-t plus a run of spaces and a trailing newline: the shape of a paste.
    let contaminated = format!(
        "  {}\n",
        w.phrase.replacen("art", "\u{ff41}\u{ff52}\u{ff54}", 1).replacen(' ', "   ", 3)
    );
    assert_ne!(contaminated.trim(), w.phrase, "the fixture must actually be contaminated");

    let _sb = Sandbox::new("f6-import-stores-normalised");
    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
        .await
        .expect("a wallet must exist before importing into it");
    zecboat_core::unlock_wallet("pw".into(), false).await.expect("unlock");
    zecboat_core::import_wallet(&contaminated, Some(BIRTHDAY))
        .await
        .expect("import must accept the contaminated phrase");

    let exported = zecboat_core::export_keys().await.expect("export");
    let stored = exported
        .rsplit_once("Seed Phrase:\n")
        .map(|(_, p)| p)
        .expect("export_keys prints the phrase after a fixed header");
    assert_eq!(
        stored, w.phrase,
        "import_wallet stored the phrase as typed; recover_wallet_from_seed stores it \
         normalised, so the same seed would export two different strings"
    );
}

/// R6. `get_viewkey` derived a key from the stored phrase and showed it, without ever
/// asking whether that key is the one in `accounts.ufvk` — the key this wallet actually
/// scans and spends with. F4 catches a phrase from a different SEED, by fingerprint; it
/// says nothing about an account row whose UFVK is not what that seed derives. Settings →
/// Get Viewkey would then hand out a key for a wallet the user is not looking at.
#[tokio::test]
async fn the_view_key_shown_is_the_one_the_wallet_scans_with() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    const BIRTHDAY: u32 = 3_400_000;
    let w = &KNOWN_WALLETS[0];
    let sb = Sandbox::new("r6-viewkey");
    zecboat_core::recover_wallet_from_seed(w.phrase, "pw".into(), Some(BIRTHDAY))
        .await
        .expect("recover");
    zecboat_core::unlock_wallet("pw".into(), false).await.expect("unlock");

    // Healthy wallet: the key shown is the account's key.
    let shown = zecboat_core::get_viewkey().await.expect("a healthy wallet shows its view key");
    let (stored, _) = stored_account(&sb.wallet_db());
    assert_eq!(shown, stored, "the view key shown differs from the account's stored UFVK");
    assert_eq!(shown, w.ufvk);

    // Same seed fingerprint, different account key: F4 stays silent, so only a check
    // against accounts.ufvk can notice. A wallet in this state must not hand out a key.
    let other = KNOWN_WALLETS[1].ufvk;
    assert_ne!(other, w.ufvk);
    rusqlite::Connection::open(sb.wallet_db())
        .unwrap()
        .execute("UPDATE accounts SET ufvk = ?1", [other])
        .unwrap();
    let err = zecboat_core::get_viewkey()
        .await
        .expect_err("the seed does not derive the account's UFVK; get_viewkey must refuse");
    let msg = err.to_string();
    assert!(
        msg.contains("does not match"),
        "the refusal must say the derived key does not match the account: {msg}"
    );
    assert!(!msg.contains(w.phrase) && !msg.contains("abandon"), "the refusal echoed the phrase");
}
