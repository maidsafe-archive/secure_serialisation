// Copyright 2015 MaidSafe.net limited.
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
//! Given a remote nacl box PublicKey this lib will securely serialise and
//! encrypt messages destined for that node. These will use authenticated encryption.
//!
//! # Authenticated encryption
//! Using public-key authenticated encryption, Bob can encrypt a confidential message specificall
//! for Alice, using Alice's public key.+
//!
//! Using Bob's public key, Alice can verify that the encrypted message was actually created by Bob
//! and was not tampered with, before eventually decrypting it.
//! Alice only needs Bob's public key, the nonce and the ciphertext. Bob should never ever share his
//! secret key, even with Alice.
//! And in order to send messages to Alice, Bob only needs Alice's public key. Alice should never
//! ever share her secret key either, even with Bob.
//! Alice can reply to Bob using the same system, without having to generate a distinct key pair.
//! The nonce doesn't have to be confidential, but it should be used with just one invocation of
//! crypto_box_open_easy() for a particular pair of public and secret keys.
//!
//! One easy way to generate a nonce is to use randombytes_buf(), considering the size of nonces
//! the risk of any random collisions is negligible. For some applications, if you wish to use
//! nonces to detect missing messages or to ignore replayed messages, it is also ok
//! to use a simple incrementing counter as a nonce. In this crate we use a random nonce wrapped
//! into the message.
//!
//! This implementation will encrypt data with a nonce and then serialise the payload. The nonce
//! is then prepended to the beginning of the message and pulled off first at the remote end.
//! This provides a clean secure mechanism for sending data between entities who have session
//! based keypairs. It SHOULD NOT be used for permanent keys.
//!
//! Where possible the precompute_* functions will lessen any cpu overhead in sending messages
//! and should be preferred. This is not enforced to allow occasional sending of messages
//! between parties using a simpler, although slower, method.
//!
//! These functions do not meant to provide non-repudiation. On the
//! contrary: they  guaranteesrepudiability. A receiver
//! can freely modify a message, and therefore cannot convince third
//! parties that this particular message came from the sender. The sender
//! and receiver are nevertheless protected against forgeries by other
//! parties. In the terminology of
//! http://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c,
//! this crate uses "public-key authenticators" rather than "public-key
//! signatures."


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
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy))]
#![cfg_attr(feature="clippy", deny(clippy_pedantic))]

extern crate sodiumoxide;
#[macro_use]
extern crate maidsafe_utilities;
extern crate rustc_serialize;

use sodiumoxide::crypto::box_;
pub use sodiumoxide::crypto::box_::{PrecomputedKey, PublicKey, SecretKey, gen_keypair};
use maidsafe_utilities::serialisation;
use rustc_serialize::{Decodable, Encodable};

/// Error types, hopefully sodiumoxide eventually defines errors properly, otherwise this makes
/// little sense really
#[derive(Debug)]
pub enum SecureSerialisationError {
    /// error form serialisation crate
    SerialisationError(serialisation::SerialisationError),
    /// unfortunately sodiumoxide uses () as error types ?
    CrytpoError,
}

impl From<serialisation::SerialisationError> for SecureSerialisationError {
    fn from(orig_error: serialisation::SerialisationError) -> Self {
        SecureSerialisationError::SerialisationError(orig_error)
    }
}

impl From<()> for SecureSerialisationError {
    fn from(_: ()) -> Self {
        SecureSerialisationError::CrytpoError
    }
}

#[derive (RustcEncodable, RustcDecodable)]
struct Payload {
    ciphertext: Vec<u8>,
    nonce: box_::Nonce,
}

/// Pre-compute a key for a session, Allows greater message throughput.
pub fn pre_compute(their_public_key: &PublicKey, our_secret_key: &SecretKey) -> PrecomputedKey {
    box_::precompute(their_public_key, our_secret_key)
}

/// Pre computed key version (less cpu intensive if many messages are transferred)
/// Prepare an encodable data element for transmission to another process whose public_key we
/// know.
pub fn pre_computed_serialise<T>(data: &T,
                                 pre_computed_key: &PrecomputedKey)
                                 -> Result<Vec<u8>, SecureSerialisationError>
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


/// Prepare an encodable data element for transmission to another process whose public_key we
/// know.
pub fn serialise<T>(data: &T,
                    their_public_key: &PublicKey,
                    our_secret_key: &SecretKey)
                    -> Result<Vec<u8>, SecureSerialisationError>
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

/// Pre computed key version (less cpu intensive if many messages are transferred)
/// Parse a data type from an encoded message, success ensures the message was from the holder of the
/// private_key related to the public_key we know of the recipient
pub fn pre_computed_deserialise<T>(message: &[u8],
                                   pre_computed_key: &PrecomputedKey)
                                   -> Result<T, SecureSerialisationError>
    where T: Decodable
{
    let payload = try!(serialisation::deserialise::<Payload>(message));
    let plain_serialised_data = try!(box_::open_precomputed(&payload.ciphertext,
                                                            &payload.nonce,
                                                            pre_computed_key));
    Ok(try!(serialisation::deserialise(&plain_serialised_data)))
}

/// Parse a data type from an encoded message, success ensures the message was from the holder of the
/// private_key related to the public_key we know of the recipient
pub fn deserialise<T>(message: &[u8],
                      their_public_key: &PublicKey,
                      our_secret_key: &SecretKey)
                      -> Result<T, SecureSerialisationError>
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
    use sodiumoxide::crypto::box_;

    #[test]
    fn alice_to_bob_message() {
        let bob_message = (vec![0u8, 1, 3, 9],
                           vec![-1i64, 888, -8765],
                           "Message from Bob for Alice, very secret".to_owned());
        let (alice_public_key, alice_secret_key) = box_::gen_keypair();
        let (bob_public_key, bob_secret_key) = box_::gen_keypair();

        let bob_encrypted_message = unwrap_result!(serialise(&bob_message,
                                                             &alice_public_key,
                                                             &bob_secret_key));

        let alice_decrypted_message: (Vec<u8>, Vec<i64>, String) =
            unwrap_result!(deserialise(&bob_encrypted_message, &bob_public_key, &alice_secret_key));

        assert_eq!(alice_decrypted_message, bob_message);
    }

    #[test]
    fn alice_to_bob_message_with_precomputed_keys() {
        let bob_message = (vec![0u8, 1, 3, 9],
                           vec![-1i64, 888, -8765],
                           "Message from Bob for Alice, very secret".to_owned());
        let (alice_public_key, alice_secret_key) = box_::gen_keypair();
        let (bob_public_key, bob_secret_key) = box_::gen_keypair();
        let bob_precomputed_key = box_::precompute(&alice_public_key, &bob_secret_key);
        let alice_precomputed_key = box_::precompute(&bob_public_key, &alice_secret_key);
        let bob_encrypted_message = unwrap_result!(pre_computed_serialise(&bob_message,
                                                                          &bob_precomputed_key));

        let alice_decrypted_message: (Vec<u8>, Vec<i64>, String) =
            unwrap_result!(pre_computed_deserialise(&bob_encrypted_message,
                                                    &alice_precomputed_key));

        assert_eq!(alice_decrypted_message, bob_message);
    }
}
