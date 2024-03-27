use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Transaction {
    from: String,
    to: String,
    amount: u64,
}

#[cfg(test)]
mod tests {
    use bls_signatures::{PrivateKey, Serialize};
    use rand::thread_rng;

    use crate::bls_aggregation::Transaction;

    #[test]
    fn aggregation_should_work() {
        let alice_private_key = PrivateKey::generate(&mut thread_rng());
        let alice = alice_private_key.public_key();
        let bob_private_key = PrivateKey::generate(&mut thread_rng());
        let bob = bob_private_key.public_key();

        let txn1: Transaction = Transaction {
            from: String::from("alice"),
            to: String::from("charlie"),
            amount: 5,
        };
        let txn2: Transaction = Transaction {
            from: String::from("bob"),
            to: String::from("charlie"),
            amount: 10,
        };

        let alice_signed_txn = alice_private_key.sign(&serde_json::to_string(&txn1).unwrap());

        let bob_signed_txn = bob_private_key.sign(&serde_json::to_string(&txn2).unwrap());

        let final_sig = bls_signatures::aggregate(&[alice_signed_txn, bob_signed_txn]).unwrap();

        let verify = bls_signatures::verify_messages(
            &final_sig,
            &[
                serde_json::to_string(&txn1).unwrap().as_bytes(),
                serde_json::to_string(&txn2).unwrap().as_bytes(),
            ],
            &[alice, bob],
        );

        assert_eq!(verify, true)
    }

    #[test]
    fn aggregation_should_not_work() {
        let alice_private_key = PrivateKey::generate(&mut thread_rng());
        let alice = alice_private_key.public_key();
        let bob_private_key = PrivateKey::generate(&mut thread_rng());
        let bob = bob_private_key.public_key();
        let hacker_private_key = PrivateKey::generate(&mut thread_rng());
        let hacker = hacker_private_key.public_key();

        let txn1: Transaction = Transaction {
            from: String::from("alice"),
            to: String::from("charlie"),
            amount: 5,
        };
        let txn2: Transaction = Transaction {
            from: String::from("bob"),
            to: String::from("charlie"),
            amount: 10,
        };

        let txn_evil = Transaction {
            from: String::from("bob"),
            to: String::from("hacker"),
            amount: 10,
        };

        let alice_signed_txn = alice_private_key.sign(&serde_json::to_string(&txn1).unwrap());

        let bob_signed_txn = bob_private_key.sign(&serde_json::to_string(&txn2).unwrap());

        let hacker_signed_txn = hacker_private_key.sign(&serde_json::to_string(&txn_evil).unwrap());

        let final_sig = bls_signatures::aggregate(&[alice_signed_txn, hacker_signed_txn]).unwrap();

        let verify = bls_signatures::verify_messages(
            &final_sig,
            &[
                serde_json::to_string(&txn1).unwrap().as_bytes(),
                serde_json::to_string(&txn_evil).unwrap().as_bytes(),
            ],
            &[alice, bob],
        );

        assert_eq!(verify, false)
    }
}
