use blst::min_sig::PublicKey;
use blst::min_sig::SecretKey;
use blst::min_sig::Signature;
use rand::TryRngCore;
use rand::rngs::OsRng;

const DOMAIN: &[u8] = b"BLS_SIG_DOMAIN_ETH2";

/// Generate a secret/public key pair
fn generate_keypair() -> (SecretKey, PublicKey) {
    // Generate 32 bytes of randomness
    let mut ikm = [0u8; 32];
    let _ = OsRng.try_fill_bytes(&mut ikm);

    // Domain tag used for domain separation
    const DST: &[u8] = b"BLS-SIG-KEYGEN-SALT-";

    let sk = SecretKey::key_gen_v5(&ikm, DST, &[]).expect("Failed to generate secret key");
    let pk = sk.sk_to_pk();
    (sk, pk)
}

/// Sign a message with the provided secret key
fn sign_message(sk: &SecretKey, message: &[u8]) -> Signature {
    sk.sign(message, DOMAIN, &[])
}

/// Aggregate a list of signatures into one
fn aggregate_signatures(sigs: &[Signature]) -> Option<Signature> {
    if sigs.is_empty() {
        return None;
    }
    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    blst::min_sig::AggregateSignature::aggregate(&sig_refs, true)
        .ok()
        .map(|agg| agg.to_signature())
}

/// Verify an aggregated signature
fn verify_aggregate(agg_sig: &Signature, pks: &[PublicKey], message: &[u8]) -> bool {
    let refs: Vec<&PublicKey> = pks.iter().collect();
    let messages: Vec<&[u8]> = vec![message; pks.len()]; // repeat same message for each pk
    let result = agg_sig.aggregate_verify(true, &messages, DOMAIN, &refs, true);

    result == blst::BLST_ERROR::BLST_SUCCESS
}

/// A mock validator
struct Validator {
    #[allow(dead_code)]
    id: usize,
    sk: SecretKey,
    pk: PublicKey,
}

impl Validator {
    fn new(id: usize) -> Self {
        let (sk, pk) = generate_keypair();
        Self { id, sk, pk }
    }

    /// Create a message like Ethereum slot-based voting
    #[allow(dead_code)]
    fn make_message(&self, slot: u64) -> Vec<u8> {
        format!("slot:{}|validator:{}", slot, self.id).into_bytes()
    }

    fn sign(&self, message: &[u8]) -> Signature {
        sign_message(&self.sk, message)
    }
}

fn main() {
    let slot = 123456;
    let validators: Vec<Validator> = (0..5).map(Validator::new).collect();

    let message = format!("slot:{}", slot).into_bytes();

    // Collect signatures for the same message
    let signatures: Vec<Signature> = validators.iter().map(|v| v.sign(&message)).collect();

    let agg_sig = aggregate_signatures(&signatures).unwrap();

    let pubkeys: Vec<PublicKey> = validators.iter().map(|v| v.pk.clone()).collect();

    let valid = verify_aggregate(&agg_sig, &pubkeys, &message);
    println!("Aggregated signature is valid: {}", valid);
}
#[cfg(test)]
mod tests {
    use super::*;
   

    // Test case to check if the key pair is generated correctly.
    #[test]
    fn test_generate_keypair() {
        let (sk, pk) = generate_keypair();

        // Secret and Public Key should not be empty
        assert!(!sk.to_bytes().is_empty(), "Secret key is empty");
        assert!(!pk.to_bytes().is_empty(), "Public key is empty");
    }

    // Test case to check message signing with a valid secret key.
    #[test]
    fn test_sign_message() {
        let (sk, _) = generate_keypair();
        let message = b"test message";

        let sig = sign_message(&sk, message);

        // The signature should not be empty
        assert!(!sig.to_bytes().is_empty(), "Signature is empty");
    }

    // Test case for aggregating signatures.
    #[test]
    fn test_aggregate_signatures() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();

        let message = b"test message";
        let sig1 = sign_message(&sk1, message);
        let sig2 = sign_message(&sk2, message);

        let signatures = vec![sig1, sig2];
        let agg_sig = aggregate_signatures(&signatures).unwrap();

        // The aggregated signature should not be empty
        assert!(!agg_sig.to_bytes().is_empty(), "Aggregated signature is empty");

        // Verify the aggregated signature
        let pubkeys = vec![pk1, pk2];
        let valid = verify_aggregate(&agg_sig, &pubkeys, message);

        // The aggregated signature should be valid
        assert!(valid, "Aggregated signature verification failed");
    }

    // Test case to check the verification of the aggregated signature with multiple validators.
    #[test]
    fn test_verify_aggregate() {
        let slot = 123456;
        let validators: Vec<Validator> = (0..5).map(Validator::new).collect();
        let message = format!("slot:{}", slot).into_bytes();

        // Collect signatures for the same message
        let signatures: Vec<Signature> = validators.iter().map(|v| v.sign(&message)).collect();

        let agg_sig = aggregate_signatures(&signatures).unwrap();

        let pubkeys: Vec<PublicKey> = validators.iter().map(|v| v.pk.clone()).collect();

        // Check that the aggregated signature is valid
        let valid = verify_aggregate(&agg_sig, &pubkeys, &message);
        assert!(valid, "Aggregated signature verification failed");
    }

    // Test case for edge case where there are no signatures to aggregate.
    #[test]
    fn test_empty_aggregate() {
        let agg_sig = aggregate_signatures(&[]);

        // The result should be None, as no signatures exist to aggregate.
        assert!(agg_sig.is_none(), "Aggregation should return None for empty input");
    }

    // Test case for edge case where there is only one signature to aggregate.
    #[test]
    fn test_single_signature_aggregate() {
        let (sk, _pk) = generate_keypair();
        let message = b"single message";

        let sig = sign_message(&sk, message);

        let agg_sig = aggregate_signatures(&[sig]).unwrap();

        // The aggregated signature should be the same as the original signature when there's only one.
        assert_eq!(agg_sig, sig, "Aggregated signature should be the same as the original signature");
    }
}