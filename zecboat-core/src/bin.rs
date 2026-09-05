use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::zip32::AccountId;
use zcash_primitives::consensus::MainNetwork;

fn main() {
    let seed = [0u8; 32];
    let usk = UnifiedSpendingKey::from_seed(&MainNetwork, &seed, AccountId::from(0)).unwrap();
    let (ua, _) = usk.default_address();
    println!("{}", ua.encode(&MainNetwork));
}
