// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! # Secure Serialisation
//!
//! Given a remote nacl box `PublicKey` this lib will securely serialise and encrypt messages
//! destined for that node.  These will use authenticated encryption.
//!
//! # Authenticated encryption
//! Using public-key authenticated encryption, Bob can encrypt a confidential message specifically
//! for Alice, using Alice's public key.
//!
//! Using Bob's public key, Alice can verify that the encrypted message was actually created by Bob
//! and was not tampered with, before eventually decrypting it.
//!
//! Alice only needs Bob's public key, the nonce and the ciphertext.  Bob should never ever share
//! his secret key, even with Alice.  And in order to send messages to Alice, Bob only needs Alice's
//! public key.  Alice should never ever share her secret key either, even with Bob.
//!
//! Alice can reply to Bob using the same system, without having to generate a distinct key pair.
//! The nonce doesn't have to be confidential, but it should be used with just one invocation of
//! `crypto_box_open_easy()` for a particular pair of public and secret keys.
//!
//! One easy way to generate a nonce is to use `randombytes_buf()`; considering the size of nonces
//! the risk of any random collisions is negligible.  For some applications, if you wish to use
//! nonces to detect missing messages or to ignore replayed messages, it is also OK to use a simple
//! incrementing counter as a nonce.  In this crate we use a random nonce wrapped into the message.
//!
//! This implementation will encrypt data with a nonce and then serialise the payload.  The nonce
//! is then prepended to the message and pulled off first at the remote end.  This provides a clean,
//! secure mechanism for sending data between entities who have session-based keypairs.  It SHOULD
//! NOT be used for permanent keys.
//!
//! Where possible the `precompute_*` functions will lessen any CPU overhead in sending messages and
//! should be preferred.  This is not enforced to allow occasional sending of messages between
//! parties using a simpler, although slower, method.
//!
//! These functions are not meant to provide non-repudiation.  On the contrary: they guarantee
//! repudiability.  A receiver can freely modify a message, and therefore cannot convince third
//! parties that this particular message came from the sender.  The sender and receiver are
//! nevertheless protected against forgeries by other parties.  In the terminology of
//! http://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c, this crate uses "public-key
//! authenticators" rather than "public-key signatures."
//!
//! # Anonymous encryption
//! Sealed boxes are designed to anonymously send messages to a recipient given its public key.
//!
//! Only the recipient can decrypt these messages, using its private key.  While the recipient can
//! verify the integrity of the message, it cannot verify the identity of the sender.  A message is
//! encrypted using an ephemeral key pair, whose secret part is destroyed right after the encryption
//! process.  Without knowing the secret key used for a given message, the sender cannot decrypt its
//! own message later.  And without additional data, a message cannot be correlated with the
//! identity of its sender.

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "https://maidsafe.net/img/favicon.ico",
       html_root_url = "https://docs.rs/secure_serialisation")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items, unknown_crate_types,
          warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
        stable_features, unconditional_recursion, unknown_lints, unsafe_code, unused,
        unused_allocation, unused_attributes, unused_comparisons, unused_features, unused_parens,
        while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, missing_copy_implementations, missing_debug_implementations,
         variant_size_differences)]

extern crate maidsafe_utilities;
#[cfg(test)]
extern crate rand;
extern crate rust_sodium;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
#[macro_use]
extern crate unwrap;
#[macro_use]
extern crate quick_error;

use maidsafe_utilities::serialisation;
use rust_sodium::crypto::box_::{self, Nonce};
pub use rust_sodium::crypto::box_::{PrecomputedKey, PublicKey, SecretKey, gen_keypair, precompute};
use rust_sodium::crypto::sealedbox;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

quick_error! {
    /// Error types.
    #[derive(Debug)]
    pub enum Error {
        /// Failure to serialize/deserialize data.
        Serialisation(e: serialisation::SerialisationError) {
            description("Error serializing/deserializing data")
            display("Error serializing/deserializing data: {}", e)
            cause(e)
            from()
        }
        /// Failure to encrypt/decrypt data.
        Crypto(_e: ()) {
            description("Crypto error")
            display("Crypto error")
            from()
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Payload {
    ciphertext: Vec<u8>,
    nonce: Nonce,
}

/// Prepare an encodable data element for transmission to another process whose public key we
/// know, and which is pre-computed.  This is less CPU-intensive than
/// [`serialise()`](fn.serialise.html) which can be useful if many messages are to be transferred.
pub fn pre_computed_serialise<T: Serialize>(
    data: &T,
    pre_computed_key: &PrecomputedKey,
) -> Result<Vec<u8>, Error> {
    let nonce = box_::gen_nonce();
    let serialised_data = serialisation::serialise(data)?;
    let full_payload = Payload {
        ciphertext: box_::seal_precomputed(&serialised_data, &nonce, pre_computed_key),
        nonce: nonce,
    };

    Ok(serialisation::serialise(&full_payload)?)
}

/// Prepare an encodable data element for transmission to another process whose public key we know.
pub fn serialise<T: Serialize>(
    data: &T,
    their_public_key: &PublicKey,
    our_secret_key: &SecretKey,
) -> Result<Vec<u8>, Error> {
    let nonce = box_::gen_nonce();
    let serialised_data = serialisation::serialise(data)?;
    let full_payload = Payload {
        ciphertext: box_::seal(&serialised_data, &nonce, their_public_key, our_secret_key),
        nonce: nonce,
    };

    Ok(serialisation::serialise(&full_payload)?)
}

/// Parse a data type from an encoded message from a sender whose public key we know, and which is
/// pre-computed.  This is less CPU-intensive than [`deserialise()`](fn.deserialise.html) which can
/// be useful if many messages are to be transferred.  Success ensures the message was from the
/// holder of the private key related to the public key we know of the sender.
pub fn pre_computed_deserialise<T: DeserializeOwned + Serialize>(
    message: &[u8],
    pre_computed_key: &PrecomputedKey,
) -> Result<T, Error> {
    let payload = serialisation::deserialise::<Payload>(message)?;
    let plain_serialised_data =
        box_::open_precomputed(&payload.ciphertext, &payload.nonce, pre_computed_key)?;
    Ok(serialisation::deserialise(&plain_serialised_data)?)
}

/// Parse a data type from an encoded message from a sender whose public key we know.  Success
/// ensures the message was from the holder of the private key related to the public key we know of
/// the sender.
pub fn deserialise<T: DeserializeOwned + Serialize>(
    message: &[u8],
    their_public_key: &PublicKey,
    our_secret_key: &SecretKey,
) -> Result<T, Error> {
    let payload = serialisation::deserialise::<Payload>(message)?;
    let plain_serialised_data = box_::open(
        &payload.ciphertext,
        &payload.nonce,
        their_public_key,
        our_secret_key,
    )?;
    Ok(serialisation::deserialise(&plain_serialised_data)?)
}

/// Prepare an encodable data element for transmission to another process, whose public key we know,
/// that does not know our public key.
pub fn anonymous_serialise<T: Serialize>(
    data: &T,
    their_public_key: &PublicKey,
) -> Result<Vec<u8>, Error> {
    let serialised_data = serialisation::serialise(data)?;
    let encrypted_data = sealedbox::seal(&serialised_data, their_public_key);
    Ok(serialisation::serialise(&encrypted_data)?)
}

/// Parse a tuple data type from an encoded message from a sender whose public key we do not know.
/// Success does not provide any guarantee of correlation between the expected and actual identity
/// of the message sender.
pub fn anonymous_deserialise<T: DeserializeOwned + Serialize>(
    message: &[u8],
    our_pub_key: &PublicKey,
    our_secret_key: &SecretKey,
) -> Result<T, Error> {
    let encrypted_data = serialisation::deserialise::<Vec<u8>>(message)?;
    let plain_serialised_data = sealedbox::open(&encrypted_data[..], our_pub_key, our_secret_key)?;
    Ok(serialisation::deserialise(&plain_serialised_data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rand, Rng};
    use rand::distributions::{IndependentSample, Range};

    // Mutate a single byte of the slice
    fn tamper(bytes: &mut [u8]) {
        let range = Range::new(0, bytes.len());
        let mut rng = ::rand::thread_rng();
        let index = range.ind_sample(&mut rng);
        bytes[index] ^= 0x01;
    }

    fn generate_random_vec<T: Rand>(size: usize) -> Vec<T> {
        ::rand::thread_rng().gen_iter().take(size).collect()
    }

    type Msg = (Vec<u8>, Vec<i64>, String);

    #[test]
    fn authenticated_encryption() {
        let bob_message1 = (
            generate_random_vec::<u8>(10),
            generate_random_vec::<i64>(100),
            "Message from Bob for Alice, very secret".to_owned(),
        );
        let bob_message2 = generate_random_vec::<u8>(1000);

        let (alice_public_key, alice_secret_key) = gen_keypair();
        let (bob_public_key, bob_secret_key) = gen_keypair();

        let bob_precomputed_key = precompute(&alice_public_key, &bob_secret_key);
        let alice_precomputed_key = precompute(&bob_public_key, &alice_secret_key);

        // Encrypt message 1 with public and private keys
        let bob_encrypted_message1 =
            unwrap!(serialise(&bob_message1, &alice_public_key, &bob_secret_key));
        // Encrypt message 2 with precomputed key
        let bob_encrypted_message2 =
            unwrap!(pre_computed_serialise(&bob_message2, &bob_precomputed_key));

        // Decrypt message 1 with public and private keys
        let mut alice_decrypted_message1: Msg = unwrap!(deserialise(
            &bob_encrypted_message1,
            &bob_public_key,
            &alice_secret_key,
        ));
        assert_eq!(alice_decrypted_message1, bob_message1);

        // Decrypt message 1 with precomputed key
        alice_decrypted_message1 = unwrap!(pre_computed_deserialise(
            &bob_encrypted_message1,
            &alice_precomputed_key,
        ));
        assert_eq!(alice_decrypted_message1, bob_message1);

        // Decrypt message 2 with public and private keys
        let mut alice_decrypted_message2: Vec<u8> = unwrap!(deserialise(
            &bob_encrypted_message2,
            &bob_public_key,
            &alice_secret_key,
        ));
        assert_eq!(alice_decrypted_message2, bob_message2);

        // Decrypt message 2 with precomputed key
        alice_decrypted_message2 = unwrap!(pre_computed_deserialise(
            &bob_encrypted_message2,
            &alice_precomputed_key,
        ));
        assert_eq!(alice_decrypted_message2, bob_message2);

        // Tamper with the encrypted message - should fail to deserialise for both methods
        let mut corrupted_message = bob_encrypted_message1.clone();
        tamper(&mut corrupted_message[..]);
        assert!(
            deserialise::<Msg>(&corrupted_message, &bob_public_key, &alice_secret_key).is_err()
        );
        assert!(
            pre_computed_deserialise::<Msg>(&corrupted_message, &alice_precomputed_key).is_err()
        );

        // Check we can't decrypt with invalid keys
        let (bad_public_key, bad_secret_key) = gen_keypair();
        assert!(
            deserialise::<Msg>(&bob_encrypted_message1, &bob_public_key, &bad_secret_key).is_err()
        );
        assert!(
            deserialise::<Msg>(&bob_encrypted_message1, &bad_public_key, &alice_secret_key).is_err()
        );
        let mut bad_precomputed_key = precompute(&bob_public_key, &bad_secret_key);
        assert!(
            pre_computed_deserialise::<Msg>(&bob_encrypted_message1, &bad_precomputed_key).is_err()
        );
        bad_precomputed_key = precompute(&bad_public_key, &alice_secret_key);
        assert!(
            pre_computed_deserialise::<Msg>(&bob_encrypted_message1, &bad_precomputed_key).is_err()
        );
    }

    #[test]
    fn anonymous_encryption() {
        let bob_message = (
            generate_random_vec::<u8>(10),
            generate_random_vec::<i64>(100),
            "Message from Bob for Alice, very secret".to_owned(),
        );
        let (alice_public_key, alice_secret_key) = gen_keypair();

        let bob_encrypted_message = unwrap!(anonymous_serialise(&bob_message, &alice_public_key));

        let alice_decrypted_message: Msg = unwrap!(anonymous_deserialise(
            &bob_encrypted_message,
            &alice_public_key,
            &alice_secret_key,
        ));
        assert_eq!(alice_decrypted_message, bob_message);

        // Tamper with the encrypted message - should fail to deserialise
        let mut corrupted_message = bob_encrypted_message.clone();
        tamper(&mut corrupted_message[..]);
        assert!(
            anonymous_deserialise::<Msg>(&corrupted_message, &alice_public_key, &alice_secret_key)
                .is_err()
        );

        // Check we can't decrypt with invalid keys
        let (bad_public_key, bad_secret_key) = gen_keypair();
        assert!(
            anonymous_deserialise::<Msg>(&bob_encrypted_message, &bad_public_key, &bad_secret_key)
                .is_err()
        );
        assert!(
            anonymous_deserialise::<Msg>(&bob_encrypted_message, &bad_public_key, &alice_secret_key)
                .is_err()
        );
        assert!(
            anonymous_deserialise::<Msg>(&bob_encrypted_message, &alice_public_key, &bad_secret_key)
                .is_err()
        );
    }

}
