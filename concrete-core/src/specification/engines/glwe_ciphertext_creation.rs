use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextEntity;
use concrete_commons::parameters::PolynomialSize;

engine_error! {
    GlweCiphertextCreationError for GlweCiphertextCreationEngine @
    EmptySlice => "The `values` slice is of size 0!",
    InvalidSliceSize => "The `values` slice size needs to be a multiple of `polynomial_size`."
}

impl<EngineError: std::error::Error> GlweCiphertextCreationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks(
        container_length: usize,
        polynomial_size: PolynomialSize,
    ) -> Result<(), Self> {
        if container_length == 0 {
            return Err(Self::EmptySlice);
        }
        if container_length % polynomial_size.0 != 0 {
            return Err(Self::InvalidSliceSize);
        }

        Ok(())
    }
}

/// A trait for engines creating a GLWE ciphertext from an arbitrary container.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation creates a GLWE ciphertext from the abitrary
/// `container`. By arbitrary here, we mean that `Container` can be any type that allows to
/// instantiate a `GlweCiphertextEntity`.
///
/// # Formal Definition
pub trait GlweCiphertextCreationEngine<Container, Ciphertext>: AbstractEngine
where
    Ciphertext: GlweCiphertextEntity,
{
    /// Creates a GLWE ciphertext from an arbitrary container.
    fn create_glwe_ciphertext(
        &mut self,
        container: Container,
        polynomial_size: PolynomialSize,
    ) -> Result<Ciphertext, GlweCiphertextCreationError<Self::EngineError>>;

    /// Unsafely creates a GLWE ciphertext from an arbitrary container.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextCreationError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn create_glwe_ciphertext_unchecked(
        &mut self,
        container: Container,
        polynomial_size: PolynomialSize,
    ) -> Ciphertext;
}
