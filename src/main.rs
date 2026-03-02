use k256::ecdsa;
use keccak_hash;
use rand::TryRng;

pub fn gen_key() -> [u8; 32] {
    let mut dest = [0u8; 32];
    rand::rng().try_fill_bytes(&mut dest);
    dest
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes
        .into_iter()
        .map(|char| format!("{:02X?}", char))
        .collect::<String>()
}

fn main() {
    let initial_slice = gen_key();
    let private_key =
        ecdsa::SigningKey::from_slice(&initial_slice).expect("Should have generated a key");
    let private_key_bytes = private_key.to_bytes();

    println!(
        "ETH Private key /!\\ DO NOT SHARE /!\\ : \n0x{}\n",
        to_hex(&private_key_bytes)
    );

    let public_key = private_key.verifying_key();
    let elliptic_point = public_key.to_encoded_point(false);
    let x_bytes = elliptic_point.x().expect("Should have x coordinate");
    let y_bytes = elliptic_point.y().expect("Should have y coordinate");
    let mut public_key_bytes = Vec::<u8>::new();
    for char in x_bytes.iter().chain(y_bytes.iter()) {
        public_key_bytes.push(*char);
    }

    println!(
        "ETH Public key : \n0x{}\n",
        to_hex(public_key_bytes.as_slice())
    );

    let mut eth_public_key_hash = [0u8; 32];
    keccak_hash::keccak_256(public_key_bytes.as_slice(), &mut eth_public_key_hash);
    let eth_public_address =
        to_hex(&eth_public_key_hash[eth_public_key_hash.len() - 20..eth_public_key_hash.len()]);

    println!("ETH public address : \n0x{}", eth_public_address);
}
