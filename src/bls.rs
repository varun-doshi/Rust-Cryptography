use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Transaction {
    from: String,
    to: String,
    amount: u64,
}

#[cfg(test)]
mod tests {
    use bls_signatures::PrivateKey;
    use rand::thread_rng;

    use crate::bls::Transaction;

    #[test]
    fn should_work() {
        let alice_private_key = PrivateKey::generate(&mut thread_rng());
        let alice = alice_private_key.public_key();
        let bob_private_key = PrivateKey::generate(&mut thread_rng());
        let bob = bob_private_key.public_key();

        let txn: Transaction = Transaction {
            from: String::from("alice"),
            to: String::from("bob"),
            amount: 10,
        };

        let serialized_message = serde_json::to_string(&txn).unwrap();

        let signed_txn = alice_private_key.sign(&serialized_message);

        let verify = alice.verify(signed_txn, &serialized_message);

        assert_eq!(verify, true)
    }

    #[test]
    fn should_not_work() {
        let alice_private_key = PrivateKey::generate(&mut thread_rng());
        let alice = alice_private_key.public_key();
        let hacker_private_key = PrivateKey::generate(&mut thread_rng());
        let hacker = hacker_private_key.public_key();
        let bob_private_key = PrivateKey::generate(&mut thread_rng());
        let bob = bob_private_key.public_key();

        let txn: Transaction = Transaction {
            from: String::from("alice"),
            to: String::from("bob"),
            amount: 10,
        };

        let hacked_Txn = Transaction {
            from: String::from("alice"),
            to: String::from("hacker"),
            amount: 10,
        };

        let serialized_message = serde_json::to_string(&txn).unwrap();
        let hacked_serialized_message = serde_json::to_string(&hacked_Txn).unwrap();
        let signed_txn = alice_private_key.sign(&serialized_message);
        let hacked_signed_txn = alice_private_key.sign(&hacked_serialized_message);
        let verify = alice.verify(hacked_signed_txn, &serialized_message);

        assert_eq!(verify, false)
    }
}
