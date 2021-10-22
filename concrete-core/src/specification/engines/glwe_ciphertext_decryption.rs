use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    GlweCiphertextDecryptionError for GlweCiphertextDecryptionEngine@
    GlweDimensionMismatch => "The ciphertext and secret key glwe dimension must be the same.",
    PolynomialSizeMismatch => "The ciphertext and secret key polynomial size must be the same."
}

/// A trait for engines decrypting glwe ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext vector containing the
/// decryption of the `input` ciphertext, under the `key` secret key.
///
/// # Formal Definition
pub trait GlweCiphertextDecryptionEngine<SecretKey, Ciphertext, PlaintextVector>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    Ciphertext: GlweCiphertextEntity<
        Representation = SecretKey::Representation,
        KeyFlavor = SecretKey::KeyFlavor,
    >,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
{
    /// Decrypts a glwe ciphertext into a plaintext vector.
    fn decrypt_glwe_ciphertext(
        &mut self,
        key: &SecretKey,
        input: &Ciphertext,
    ) -> Result<PlaintextVector, GlweCiphertextDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts a glwe ciphertext into a plaintext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextDecryptionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn decrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        input: &Ciphertext,
    ) -> PlaintextVector;
}