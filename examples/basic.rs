// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! This is a very basic example that demonstrates how to encrypt/decrypt data with
//! `secure_serialisation` crate.

extern crate secure_serialisation;
extern crate rust_sodium;
#[macro_use]
extern crate unwrap;

use rust_sodium::crypto::box_::gen_keypair;
use secure_serialisation::{deserialise, serialise};

fn main() {
    let (our_pub_key, our_sec_key) = gen_keypair();
    let (their_pub_key, their_sec_key) = gen_keypair();

    let data = "hello".to_string();
    let encrypted_data = unwrap!(serialise(&data, &their_pub_key, &our_sec_key));
    println!("Encrypted data: {:?}", encrypted_data);

    let data: String = unwrap!(deserialise(&encrypted_data, &our_pub_key, &their_sec_key));
    println!("Decrypted data: {:?}", data);
}
