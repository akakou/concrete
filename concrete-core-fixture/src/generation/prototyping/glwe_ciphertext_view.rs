use crate::generation::prototypes::{
    GlweCiphertextMutViewPrototype, GlweCiphertextViewPrototype,
    ProtoBinaryGlweCiphertextMutView32, ProtoBinaryGlweCiphertextMutView64,
    ProtoBinaryGlweCiphertextView32, ProtoBinaryGlweCiphertextView64,
};
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};
use concrete_commons::parameters::PolynomialSize;

/// A trait allowing to manipulate GLWE ciphertext view prototypes.
pub trait PrototypesGlweCiphertextView<Precision: IntegerPrecision> {
    type GlweCiphertextViewProto: GlweCiphertextViewPrototype<Precision = Precision>;
    fn transform_raw_to_ciphertext_view(
        &mut self,
        raw: Vec<Precision::Raw>,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweCiphertextViewProto;
    fn transform_ciphertext_view_to_raw(
        &mut self,
        ciphertext_view: &Self::GlweCiphertextViewProto,
    ) -> (Vec<Precision::Raw>, PolynomialSize);
}

impl PrototypesGlweCiphertextView<Precision32> for Maker {
    type GlweCiphertextViewProto = ProtoBinaryGlweCiphertextView32;
    fn transform_raw_to_ciphertext_view(
        &mut self,
        raw: Vec<u32>,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweCiphertextViewProto {
        ProtoBinaryGlweCiphertextView32(raw, polynomial_size)
    }
    fn transform_ciphertext_view_to_raw(
        &mut self,
        ciphertext_view: &Self::GlweCiphertextViewProto,
    ) -> (Vec<u32>, PolynomialSize) {
        (ciphertext_view.0.to_owned(), ciphertext_view.1.to_owned())
    }
}

impl PrototypesGlweCiphertextView<Precision64> for Maker {
    type GlweCiphertextViewProto = ProtoBinaryGlweCiphertextView64;
    fn transform_raw_to_ciphertext_view(
        &mut self,
        raw: Vec<u64>,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweCiphertextViewProto {
        ProtoBinaryGlweCiphertextView64(raw, polynomial_size)
    }
    fn transform_ciphertext_view_to_raw(
        &mut self,
        ciphertext_view: &Self::GlweCiphertextViewProto,
    ) -> (Vec<u64>, PolynomialSize) {
        (ciphertext_view.0.to_owned(), ciphertext_view.1.to_owned())
    }
}

// A trait allowing to manipulate GLWE ciphertext mut view prototypes.
pub trait PrototypesGlweCiphertextMutView<Precision: IntegerPrecision> {
    type GlweCiphertextMutViewProto: GlweCiphertextMutViewPrototype<Precision = Precision>;
    fn transform_raw_to_ciphertext_mut_view(
        &mut self,
        raw: Vec<Precision::Raw>,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweCiphertextMutViewProto;
    fn transform_ciphertext_mut_view_to_raw(
        &mut self,
        ciphertext_view: &Self::GlweCiphertextMutViewProto,
    ) -> (Vec<Precision::Raw>, PolynomialSize);
}

impl PrototypesGlweCiphertextMutView<Precision32> for Maker {
    type GlweCiphertextMutViewProto = ProtoBinaryGlweCiphertextMutView32;
    fn transform_raw_to_ciphertext_mut_view(
        &mut self,
        raw: Vec<u32>,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweCiphertextMutViewProto {
        ProtoBinaryGlweCiphertextMutView32(raw, polynomial_size)
    }
    fn transform_ciphertext_mut_view_to_raw(
        &mut self,
        ciphertext_view: &Self::GlweCiphertextMutViewProto,
    ) -> (Vec<u32>, PolynomialSize) {
        (ciphertext_view.0.to_owned(), ciphertext_view.1.to_owned())
    }
}

impl PrototypesGlweCiphertextMutView<Precision64> for Maker {
    type GlweCiphertextMutViewProto = ProtoBinaryGlweCiphertextMutView64;
    fn transform_raw_to_ciphertext_mut_view(
        &mut self,
        raw: Vec<u64>,
        polynomial_size: PolynomialSize,
    ) -> Self::GlweCiphertextMutViewProto {
        ProtoBinaryGlweCiphertextMutView64(raw, polynomial_size)
    }
    fn transform_ciphertext_mut_view_to_raw(
        &mut self,
        ciphertext_view: &Self::GlweCiphertextMutViewProto,
    ) -> (Vec<u64>, PolynomialSize) {
        (ciphertext_view.0.to_owned(), ciphertext_view.1.to_owned())
    }
}
