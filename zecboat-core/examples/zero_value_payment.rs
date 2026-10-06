//! Does the wallet library's payment request accept zero-value payments that carry a memo?
//! (Open question 1 of the record-in-memos design, 2026-10-05.) Pure construction: no wallet,
//! no network. Uses the registry's published address as a stand-in recipient.
use zcash_address::ZcashAddress;
use zcash_client_backend::zip321::{Payment, TransactionRequest};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

fn main() -> anyhow::Result<()> {
    let addr = ZcashAddress::try_from_encoded(zecboat_core::issuance_v1::REGISTRY_ADDRESS)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut memo = [0u8; 512];
    memo[0] = 0xF5;
    memo[1..5].copy_from_slice(b"WKL1");
    let carrier = Payment::new(addr.clone(), Some(Zatoshis::from_u64(10_000).unwrap()), Some(MemoBytes::from_bytes(b"{}").unwrap()), None, None, vec![]);
    println!("carrier payment: {}", if carrier.is_ok() { "ok".to_string() } else { format!("{:?}", carrier.as_ref().err()) });
    let mut payments = vec![carrier.map_err(|e| anyhow::anyhow!("{e:?}"))?];
    for i in 0..31 {
        let mut m = memo;
        m[13] = i;
        match Payment::new(addr.clone(), Some(Zatoshis::ZERO), Some(MemoBytes::from_bytes(&m).unwrap()), None, None, vec![]) {
            Ok(p) => payments.push(p),
            Err(e) => {
                println!("zero-value payment with a memo: REFUSED: {e:?}");
                return Ok(());
            }
        }
    }
    println!("zero-value payments with a memo: 31 accepted");
    match TransactionRequest::new(payments) {
        Ok(r) => println!("one request of {} payments: accepted; total {:?}", r.payments().len(), r.total()),
        Err(e) => println!("one request of 32 payments: REFUSED: {e:?}"),
    }
    Ok(())
}
