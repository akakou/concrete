use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextEntity;

engine_error! {
    GlweCiphertextRetrievalError for GlweCiphertextRetrievalEngine @
}

/// A trait for engines retrieving the content of the container from a GLWE ciphertext consuming it
/// in the process.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation retrieves the content of the container from the
/// `input` GLWE ciphertext consuming it in the process.
///
/// # Formal Definition
pub trait GlweCiphertextRetrievalEngine<Ciphertext, Container>: AbstractEngine
where
    Ciphertext: GlweCiphertextEntity,
{
    /// Retrieves the content of the container from a GLWE ciphertext, consuming it in the process.
    fn retrieve_glwe_ciphertext(
        &mut self,
        ciphertext: Ciphertext,
    ) -> Result<Container, GlweCiphertextRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves the content of the container from a GLWE ciphertext, consuming it in the
    /// process.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextRetrievalError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn retrieve_glwe_ciphertext_unchecked(&mut self, ciphertext: Ciphertext) -> Container;
}
