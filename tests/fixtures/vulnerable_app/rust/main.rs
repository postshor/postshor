use rsa::{RsaPrivateKey, Pkcs1v15Encrypt};
use x25519_dalek::{EphemeralSecret, PublicKey};
use ml_kem::MlKem768;

fn main() {
    let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
}
