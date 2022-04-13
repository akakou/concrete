use crate::generation::{IntegerPrecision, Precision32, Precision64};
use concrete_core::prelude::markers::{BinaryKeyDistribution, KeyDistributionMarker};

/// A trait implemented by lwe ciphertext view prototypes.
pub trait LweCiphertextMutViewPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary LWE ciphertext mutable view.
// We store a vector to allow easier memory management for synthesizing and unsynthesizing
pub struct ProtoBinaryLweCiphertextMutView32(pub(crate) Vec<u32>);
impl LweCiphertextMutViewPrototype for ProtoBinaryLweCiphertextMutView32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary LWE ciphertext mutable view.
// We store a vector to allow easier memory management for synthesizing and unsynthesizing
pub struct ProtoBinaryLweCiphertextMutView64(pub(crate) Vec<u64>);
impl LweCiphertextMutViewPrototype for ProtoBinaryLweCiphertextMutView64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}

pub trait LweCiphertextViewPrototype {
    type KeyDistribution: KeyDistributionMarker;
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit binary LWE ciphertext view.
// We store a vector to allow easier memory management for synthesizing and unsynthesizing
pub struct ProtoBinaryLweCiphertextView32(pub(crate) Vec<u32>);
impl LweCiphertextViewPrototype for ProtoBinaryLweCiphertextView32 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit binary LWE ciphertext view.
// We store a vector to allow easier memory management for synthesizing and unsynthesizing
pub struct ProtoBinaryLweCiphertextView64(pub(crate) Vec<u64>);
impl LweCiphertextViewPrototype for ProtoBinaryLweCiphertextView64 {
    type KeyDistribution = BinaryKeyDistribution;
    type Precision = Precision64;
}
