use crate::generation::prototypes::{
    LweCiphertextMutViewPrototype, LweCiphertextViewPrototype, ProtoBinaryLweCiphertextMutView32,
    ProtoBinaryLweCiphertextMutView64, ProtoBinaryLweCiphertextView32,
    ProtoBinaryLweCiphertextView64,
};
use crate::generation::{IntegerPrecision, Maker, Precision32, Precision64};

/// A trait allowing to manipulate LWE ciphertext view prototypes.
pub trait PrototypesLweCiphertextView<Precision: IntegerPrecision> {
    type LweCiphertextViewProto: LweCiphertextViewPrototype<Precision = Precision>;
    fn transform_raw_to_ciphertext_view(
        &mut self,
        raw: Vec<Precision::Raw>,
    ) -> Self::LweCiphertextViewProto;
    fn transform_ciphertext_view_to_raw(
        &mut self,
        ciphertext_view: &Self::LweCiphertextViewProto,
    ) -> Vec<Precision::Raw>;
}

impl PrototypesLweCiphertextView<Precision32> for Maker {
    type LweCiphertextViewProto = ProtoBinaryLweCiphertextView32;
    fn transform_raw_to_ciphertext_view(&mut self, raw: Vec<u32>) -> Self::LweCiphertextViewProto {
        ProtoBinaryLweCiphertextView32(raw)
    }
    fn transform_ciphertext_view_to_raw(
        &mut self,
        ciphertext_view: &Self::LweCiphertextViewProto,
    ) -> Vec<u32> {
        ciphertext_view.0.to_owned()
    }
}

impl PrototypesLweCiphertextView<Precision64> for Maker {
    type LweCiphertextViewProto = ProtoBinaryLweCiphertextView64;
    fn transform_raw_to_ciphertext_view(&mut self, raw: Vec<u64>) -> Self::LweCiphertextViewProto {
        ProtoBinaryLweCiphertextView64(raw)
    }
    fn transform_ciphertext_view_to_raw(
        &mut self,
        ciphertext_view: &Self::LweCiphertextViewProto,
    ) -> Vec<u64> {
        ciphertext_view.0.to_owned()
    }
}

// A trait allowing to manipulate LWE ciphertext mut view prototypes.
pub trait PrototypesLweCiphertextMutView<Precision: IntegerPrecision> {
    type LweCiphertextMutViewProto: LweCiphertextMutViewPrototype<Precision = Precision>;
    fn transform_raw_to_ciphertext_mut_view(
        &mut self,
        raw: Vec<Precision::Raw>,
    ) -> Self::LweCiphertextMutViewProto;
    fn transform_ciphertext_mut_view_to_raw(
        &mut self,
        ciphertext_view: &Self::LweCiphertextMutViewProto,
    ) -> Vec<Precision::Raw>;
}

impl PrototypesLweCiphertextMutView<Precision32> for Maker {
    type LweCiphertextMutViewProto = ProtoBinaryLweCiphertextMutView32;
    fn transform_raw_to_ciphertext_mut_view(
        &mut self,
        raw: Vec<u32>,
    ) -> Self::LweCiphertextMutViewProto {
        ProtoBinaryLweCiphertextMutView32(raw)
    }
    fn transform_ciphertext_mut_view_to_raw(
        &mut self,
        ciphertext_view: &Self::LweCiphertextMutViewProto,
    ) -> Vec<u32> {
        ciphertext_view.0.to_owned()
    }
}

impl PrototypesLweCiphertextMutView<Precision64> for Maker {
    type LweCiphertextMutViewProto = ProtoBinaryLweCiphertextMutView64;
    fn transform_raw_to_ciphertext_mut_view(
        &mut self,
        raw: Vec<u64>,
    ) -> Self::LweCiphertextMutViewProto {
        ProtoBinaryLweCiphertextMutView64(raw)
    }
    fn transform_ciphertext_mut_view_to_raw(
        &mut self,
        ciphertext_view: &Self::LweCiphertextMutViewProto,
    ) -> Vec<u64> {
        ciphertext_view.0.to_owned()
    }
}
