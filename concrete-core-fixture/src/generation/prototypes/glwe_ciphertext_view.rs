use crate::generation::{IntegerPrecision, Precision32, Precision64};
use concrete_commons::parameters::PolynomialSize;
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};

/// A trait implemented by glwe ciphertext view prototypes.
pub trait GlweCiphertextMutViewPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary GLWE ciphertext mutable view.
// We store a vector to allow easier memory management for synthesizing and unsynthesizing
pub struct ProtoBinaryGlweCiphertextMutView32(pub(crate) Vec<u32>, pub(crate) PolynomialSize);
impl GlweCiphertextMutViewPrototype for ProtoBinaryGlweCiphertextMutView32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary GLWE ciphertext mutable view.
// We store a vector to allow easier memory management for synthesizing and unsynthesizing
pub struct ProtoBinaryGlweCiphertextMutView64(pub(crate) Vec<u64>, pub(crate) PolynomialSize);
impl GlweCiphertextMutViewPrototype for ProtoBinaryGlweCiphertextMutView64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}

pub trait GlweCiphertextViewPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary GLWE ciphertext view.
// We store a vector to allow easier memory management for synthesizing and unsynthesizing
pub struct ProtoBinaryGlweCiphertextView32(pub(crate) Vec<u32>, pub(crate) PolynomialSize);
impl GlweCiphertextViewPrototype for ProtoBinaryGlweCiphertextView32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary GLWE ciphertext view.
// We store a vector to allow easier memory management for synthesizing and unsynthesizing
pub struct ProtoBinaryGlweCiphertextView64(pub(crate) Vec<u64>, pub(crate) PolynomialSize);
impl GlweCiphertextViewPrototype for ProtoBinaryGlweCiphertextView64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
