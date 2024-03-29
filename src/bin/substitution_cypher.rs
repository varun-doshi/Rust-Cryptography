//Substitution cypher on plaintext with key(int)
//key taken:23
//process: a+key=97+23=120=x

//Run using: cargo run --bin substitution_cypher

use std::ops::{Add, Sub};
extern crate base64;

fn main() {
    let plaintext = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."; // Input plaintext
    let key = 23; // Secret key

    // Encrypt plaintext
    let ciphertext = encrypt(plaintext, key);
    let base64_encoded = base64::encode(&ciphertext);
    println!("base64 encoded: {}", base64_encoded);

    // // Decrypt ciphertext
    println!("");
    let decrypted_text = decrypt(&ciphertext, key);
    println!(
        "Decrypted text: {:?}",
        String::from_utf8(decrypted_text).unwrap()
    );
}

fn encrypt(plaintext: &str, key: u8) -> Vec<u8> {
    let plaintext_bytes = plaintext.as_bytes();
    let mut ciphertext = Vec::new();
    for bytes in plaintext_bytes {
        let cypher_byte = (bytes.add(key)) % 255;
        ciphertext.push(cypher_byte);
    }
    ciphertext
}

fn decrypt(ciphertext: &Vec<u8>, key: u8) -> Vec<u8> {
    let mut plaintext = Vec::new();
    for bytes in ciphertext {
        let cypher_byte = (bytes.sub(key)) % 255;
        plaintext.push(cypher_byte);
    }
    plaintext
}
