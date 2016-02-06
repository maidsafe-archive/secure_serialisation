// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! # Secure Serialisation
//!
//! Given a remote nacl box PublicKey this lib will securely serialise and encrypt messages destined
//! for that node.  These will use authenticated encryption.
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
//! These functions are not meant to provide non-repudiation.  On the contrary: they  guarantee
//! repudiability.  A receiver can freely modify a message, and therefore cannot convince third
//! parties that this particular message came from the sender.  The sender and receiver are
//! nevertheless protected against forgeries by other parties.  In the terminology of
//! http://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c, this crate uses "public-key
//! authenticators" rather than "public-key signatures."

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/secure_serialisation")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]

#[macro_use]
extern crate maidsafe_utilities;
#[cfg(test)]
extern crate rand;
extern crate rustc_serialize;
extern crate sodiumoxide;

pub use sodiumoxide::crypto::box_::{PrecomputedKey, PublicKey, SecretKey, gen_keypair, precompute};

use sodiumoxide::crypto::box_::{self, Nonce};
use maidsafe_utilities::serialisation;
use rustc_serialize::{Decodable, Encodable};

/// Error types.
///
/// Hopefully sodiumoxide eventually defines errors properly, otherwise this makes little sense.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Error {
    SerialisationError(serialisation::SerialisationError),
    CryptoError,
}

impl From<serialisation::SerialisationError> for Error {
    fn from(orig_error: serialisation::SerialisationError) -> Self {
        Error::SerialisationError(orig_error)
    }
}

impl From<()> for Error {
    fn from(_: ()) -> Self {
        Error::CryptoError
    }
}

#[derive(RustcEncodable, RustcDecodable)]
struct Payload {
    ciphertext: Vec<u8>,
    nonce: Nonce,
}

/// Prepare an encodable data element for transmission to another process whose public key we
/// know, and which is pre-computed.  This is less CPU-intensive than
/// [`serialise()`](fn.serialise.html) which can be useful if many messages are to be transferred.
pub fn pre_computed_serialise<T>(data: &T,
                                 pre_computed_key: &PrecomputedKey)
                                 -> Result<Vec<u8>, Error>
    where T: Encodable
{
    let nonce = box_::gen_nonce();
    let serialised_data = try!(serialisation::serialise(data));
    let full_payload = Payload {
        ciphertext: box_::seal_precomputed(&serialised_data, &nonce, pre_computed_key),
        nonce: nonce,
    };

    Ok(try!(serialisation::serialise(&full_payload)))
}

/// Prepare an encodable data element for transmission to another process whose public key we know.
pub fn serialise<T>(data: &T,
                    their_public_key: &PublicKey,
                    our_secret_key: &SecretKey)
                    -> Result<Vec<u8>, Error>
    where T: Encodable
{
    let nonce = box_::gen_nonce();
    let serialised_data = try!(serialisation::serialise(data));
    let full_payload = Payload {
        ciphertext: box_::seal(&serialised_data, &nonce, their_public_key, our_secret_key),
        nonce: nonce,
    };

    Ok(try!(serialisation::serialise(&full_payload)))
}

/// Parse a data type from an encoded message from a sender whose public key we know, and which is
/// pre-computed.  This is less CPU-intensive than [`deserialise()`](fn.deserialise.html) which can
/// be useful if many messages are to be transferred.  Success ensures the message was from the
/// holder of the private key related to the public key we know of the sender.
pub fn pre_computed_deserialise<T>(message: &[u8],
                                   pre_computed_key: &PrecomputedKey)
                                   -> Result<T, Error>
    where T: Decodable
{
    let payload = try!(serialisation::deserialise::<Payload>(message));
    let plain_serialised_data = try!(box_::open_precomputed(&payload.ciphertext,
                                                            &payload.nonce,
                                                            pre_computed_key));
    Ok(try!(serialisation::deserialise(&plain_serialised_data)))
}

/// Parse a data type from an encoded message from a sender whose public key we know.  Success
/// ensures the message was from the holder of the private key related to the public key we know of
/// the sender.
pub fn deserialise<T>(message: &[u8],
                      their_public_key: &PublicKey,
                      our_secret_key: &SecretKey)
                      -> Result<T, Error>
    where T: Decodable
{
    let payload = try!(serialisation::deserialise::<Payload>(message));
    let plain_serialised_data = try!(box_::open(&payload.ciphertext,
                                                &payload.nonce,
                                                their_public_key,
                                                our_secret_key));
    Ok(try!(serialisation::deserialise(&plain_serialised_data)))
}



#[cfg(test)]
mod test {
    use super::*;
    use rand;
    use rand::distributions::{IndependentSample, Range};

    // Mutate a single byte of the slice
    fn tamper(bytes: &mut [u8]) {
        let range = Range::new(0, bytes.len());
        let mut rng = rand::thread_rng();
        let index = range.ind_sample(&mut rng);
        bytes[index] ^= 0x01;
    }

    #[test]
    fn alice_to_bob_message() {
        let bob_message = (vec![0u8, 1, 3, 9],
                           vec![-1i64, 888, -8765],
                           "Message from Bob for Alice, very secret".to_owned());
        let (alice_public_key, alice_secret_key) = gen_keypair();
        let (bob_public_key, bob_secret_key) = gen_keypair();

        let bob_encrypted_message = unwrap_result!(serialise(&bob_message,
                                                             &alice_public_key,
                                                             &bob_secret_key));

        let alice_decrypted_message: (Vec<u8>, Vec<i64>, String) =
            unwrap_result!(deserialise(&bob_encrypted_message, &bob_public_key, &alice_secret_key));
        assert_eq!(alice_decrypted_message, bob_message);

        // Tamper with the encrypted message - should fail to deserialise
        let mut corrupted_message = bob_encrypted_message.clone();
        tamper(&mut corrupted_message[..]);
        assert!(deserialise::<(Vec<u8>, Vec<i64>, String)>(&corrupted_message,
                                                           &bob_public_key,
                                                           &alice_secret_key)
                    .is_err());

        // Tamper with the public key - should fail to deserialise
        let mut corrupted_public_key = bob_public_key.clone();
        tamper(&mut corrupted_public_key.0);
        assert!(deserialise::<(Vec<u8>, Vec<i64>, String)>(&bob_encrypted_message,
                                                           &corrupted_public_key,
                                                           &alice_secret_key)
                    .is_err());

        // Tamper with the private key - should fail to deserialise
        let mut corrupted_secret_key = alice_secret_key.clone();
        tamper(&mut corrupted_secret_key.0);
        assert!(deserialise::<(Vec<u8>, Vec<i64>, String)>(&bob_encrypted_message,
                                                           &bob_public_key,
                                                           &corrupted_secret_key)
                    .is_err());
    }

    #[test]
    fn alice_to_bob_message_with_precomputed_keys() {
        let bob_message = (vec![0u8, 1, 3, 9],
                           vec![-1i64, 888, -8765],
                           "Message from Bob for Alice, very secret".to_owned());
        let (alice_public_key, alice_secret_key) = gen_keypair();
        let (bob_public_key, bob_secret_key) = gen_keypair();
        let bob_precomputed_key = precompute(&alice_public_key, &bob_secret_key);
        let alice_precomputed_key = precompute(&bob_public_key, &alice_secret_key);
        let bob_encrypted_message = unwrap_result!(pre_computed_serialise(&bob_message,
                                                                          &bob_precomputed_key));

        let alice_decrypted_message: (Vec<u8>, Vec<i64>, String) =
            unwrap_result!(pre_computed_deserialise(&bob_encrypted_message,
                                                    &alice_precomputed_key));
        assert_eq!(alice_decrypted_message, bob_message);

        // Tamper with the encrypted message - should fail to deserialise
        let mut corrupted_message = bob_encrypted_message.clone();
        tamper(&mut corrupted_message[..]);
        assert!(pre_computed_deserialise::<(Vec<u8>, Vec<i64>, String)>(&corrupted_message,
                                                                        &alice_precomputed_key)
                    .is_err());

        // Use wrong key - should fail to deserialise
        let wrong_key = precompute(&alice_public_key, &alice_secret_key);
        assert!(pre_computed_deserialise::<(Vec<u8>, Vec<i64>, String)>(&bob_encrypted_message,
                                                                        &wrong_key)
                    .is_err());
    }
}
