use crate::generation::prototyping::{PrototypesLweCiphertextMutView, PrototypesLweCiphertextView};
use crate::generation::IntegerPrecision;
use concrete_core::prelude::LweCiphertextEntity;

/// A trait allowing to synthesize an actual LweCiphertextView entity from a prototype.
pub trait SynthesizesLweCiphertextView<'a, Precision: IntegerPrecision, LweCiphertextView: 'a>:
    PrototypesLweCiphertextView<Precision>
where
    LweCiphertextView: LweCiphertextEntity,
{
    fn synthesize_lwe_ciphertext_view(
        &mut self,
        prototype: &Self::LweCiphertextViewProto,
    ) -> LweCiphertextView;
    fn unsynthesize_lwe_ciphertext_view(
        &mut self,
        entity: LweCiphertextView,
    ) -> Self::LweCiphertextViewProto;
    fn destroy_lwe_ciphertext_view(
        &mut self,
        entity: LweCiphertextView,
        drop_underlying_memory: bool,
    );
}

/// A trait allowing to synthesize an actual LweCiphertextMutView entity from a prototype.
pub trait SynthesizesLweCiphertextMutView<'a, Precision: IntegerPrecision, LweCiphertextMutView: 'a>:
    PrototypesLweCiphertextMutView<Precision>
where
    LweCiphertextMutView: LweCiphertextEntity,
{
    fn synthesize_lwe_ciphertext_mut_view(
        &mut self,
        prototype: &Self::LweCiphertextMutViewProto,
    ) -> LweCiphertextMutView;
    fn unsynthesize_lwe_ciphertext_mut_view(
        &mut self,
        entity: LweCiphertextMutView,
    ) -> Self::LweCiphertextMutViewProto;
    fn destroy_lwe_ciphertext_mut_view(&mut self, entity: LweCiphertextMutView);
}

#[cfg(feature = "backend_core")]
mod backend_core {
    use crate::generation::prototypes::{
        ProtoBinaryLweCiphertextView32, ProtoBinaryLweCiphertextView64,
    };
    use crate::generation::synthesizing::SynthesizesLweCiphertextView;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        DestructionEngine, LweCiphertextCreationEngine, LweCiphertextRetrievalEngine,
        LweCiphertextView32, LweCiphertextView64,
    };

    impl<'a> SynthesizesLweCiphertextView<'a, Precision32, LweCiphertextView32<'a>> for Maker {
        fn synthesize_lwe_ciphertext_view(
            &mut self,
            prototype: &Self::LweCiphertextViewProto,
        ) -> LweCiphertextView32<'a> {
            self.core_engine
                .create_lwe_ciphertext(prototype.0.clone().leak() as &[u32])
                .unwrap()
        }

        fn unsynthesize_lwe_ciphertext_view(
            &mut self,
            entity: LweCiphertextView32,
        ) -> Self::LweCiphertextViewProto {
            let slice = self.core_engine.retrieve_lwe_ciphertext(entity).unwrap();
            ProtoBinaryLweCiphertextView32(unsafe {
                Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len())
            })
        }

        fn destroy_lwe_ciphertext_view(
            &mut self,
            entity: LweCiphertextView32,
            drop_underlying_memory: bool,
        ) {
            // We don't know if this the last view referring to the slice it contains, so let the
            // programmer tell us if that's the case.
            if drop_underlying_memory {
                // If requested re-construct the vector so that it frees memory when it's dropped
                let slice = self.core_engine.retrieve_lwe_ciphertext(entity).unwrap();
                unsafe {
                    Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len())
                };
            } else {
                self.core_engine.destroy(entity).unwrap();
            }
        }
    }

    impl<'a> SynthesizesLweCiphertextView<'a, Precision64, LweCiphertextView64<'a>> for Maker {
        fn synthesize_lwe_ciphertext_view(
            &mut self,
            prototype: &Self::LweCiphertextViewProto,
        ) -> LweCiphertextView64<'a> {
            self.core_engine
                .create_lwe_ciphertext(prototype.0.clone().leak() as &[u64])
                .unwrap()
        }

        fn unsynthesize_lwe_ciphertext_view(
            &mut self,
            entity: LweCiphertextView64,
        ) -> Self::LweCiphertextViewProto {
            let slice = self.core_engine.retrieve_lwe_ciphertext(entity).unwrap();
            ProtoBinaryLweCiphertextView64(unsafe {
                Vec::from_raw_parts(slice.as_ptr() as *mut u64, slice.len(), slice.len())
            })
        }

        fn destroy_lwe_ciphertext_view(
            &mut self,
            entity: LweCiphertextView64,
            drop_underlying_memory: bool,
        ) {
            // We don't know if this the last view referring to the slice it contains, so let the
            // programmer tell us if that's the case.
            if drop_underlying_memory {
                // If requested re-construct the vector so that it frees memory when it's dropped
                let slice = self.core_engine.retrieve_lwe_ciphertext(entity).unwrap();
                unsafe {
                    Vec::from_raw_parts(slice.as_ptr() as *mut u64, slice.len(), slice.len())
                };
            } else {
                self.core_engine.destroy(entity).unwrap();
            }
        }
    }

    use crate::generation::prototypes::{
        ProtoBinaryLweCiphertextMutView32, ProtoBinaryLweCiphertextMutView64,
    };
    use crate::generation::synthesizing::SynthesizesLweCiphertextMutView;
    use concrete_core::prelude::{LweCiphertextMutView32, LweCiphertextMutView64};

    impl<'a> SynthesizesLweCiphertextMutView<'a, Precision32, LweCiphertextMutView32<'a>> for Maker {
        fn synthesize_lwe_ciphertext_mut_view(
            &mut self,
            prototype: &Self::LweCiphertextMutViewProto,
        ) -> LweCiphertextMutView32<'a> {
            self.core_engine
                .create_lwe_ciphertext(prototype.0.clone().leak())
                .unwrap()
        }

        fn unsynthesize_lwe_ciphertext_mut_view(
            &mut self,
            entity: LweCiphertextMutView32,
        ) -> Self::LweCiphertextMutViewProto {
            let slice = self.core_engine.retrieve_lwe_ciphertext(entity).unwrap();
            ProtoBinaryLweCiphertextMutView32(unsafe {
                Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len())
            })
        }

        fn destroy_lwe_ciphertext_mut_view(&mut self, entity: LweCiphertextMutView32) {
            // There should be only one mutable reference to memory, so re-construct the vector so
            // that it frees memory when it's dropped
            let slice = self.core_engine.retrieve_lwe_ciphertext(entity).unwrap();
            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }

    impl<'a> SynthesizesLweCiphertextMutView<'a, Precision64, LweCiphertextMutView64<'a>> for Maker {
        fn synthesize_lwe_ciphertext_mut_view(
            &mut self,
            prototype: &Self::LweCiphertextMutViewProto,
        ) -> LweCiphertextMutView64<'a> {
            self.core_engine
                .create_lwe_ciphertext(prototype.0.clone().leak())
                .unwrap()
        }

        fn unsynthesize_lwe_ciphertext_mut_view(
            &mut self,
            entity: LweCiphertextMutView64,
        ) -> Self::LweCiphertextMutViewProto {
            let slice = self.core_engine.retrieve_lwe_ciphertext(entity).unwrap();
            ProtoBinaryLweCiphertextMutView64(unsafe {
                Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len())
            })
        }

        fn destroy_lwe_ciphertext_mut_view(&mut self, entity: LweCiphertextMutView64) {
            // There should be only one mutable reference to memory, so re-construct the vector so
            // that it frees memory when it's dropped
            let slice = self.core_engine.retrieve_lwe_ciphertext(entity).unwrap();
            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }
}
