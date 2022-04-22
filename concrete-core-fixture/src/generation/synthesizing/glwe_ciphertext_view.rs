use crate::generation::prototyping::{
    PrototypesGlweCiphertextMutView, PrototypesGlweCiphertextView,
};
use crate::generation::IntegerPrecision;
use concrete_core::prelude::GlweCiphertextEntity;

/// A trait allowing to synthesize an actual GlweCiphertextView entity from a prototype.
pub trait SynthesizesGlweCiphertextView<'a, Precision: IntegerPrecision, GlweCiphertextView: 'a>:
    PrototypesGlweCiphertextView<Precision>
where
    GlweCiphertextView: GlweCiphertextEntity,
{
    fn synthesize_glwe_ciphertext_view(
        &mut self,
        prototype: &Self::GlweCiphertextViewProto,
    ) -> GlweCiphertextView;
    fn unsynthesize_glwe_ciphertext_view(
        &mut self,
        entity: GlweCiphertextView,
    ) -> Self::GlweCiphertextViewProto;
    fn destroy_glwe_ciphertext_view(
        &mut self,
        entity: GlweCiphertextView,
        drop_underlying_memory: bool,
    );
}

/// A trait allowing to synthesize an actual GlweCiphertextMutView entity from a prototype.
pub trait SynthesizesGlweCiphertextMutView<
    'a,
    Precision: IntegerPrecision,
    GlweCiphertextMutView: 'a,
>: PrototypesGlweCiphertextMutView<Precision> where
    GlweCiphertextMutView: GlweCiphertextEntity,
{
    fn synthesize_glwe_ciphertext_mut_view(
        &mut self,
        prototype: &Self::GlweCiphertextMutViewProto,
    ) -> GlweCiphertextMutView;
    fn unsynthesize_glwe_ciphertext_mut_view(
        &mut self,
        entity: GlweCiphertextMutView,
    ) -> Self::GlweCiphertextMutViewProto;
    fn destroy_glwe_ciphertext_mut_view(&mut self, entity: GlweCiphertextMutView);
}

#[cfg(feature = "backend_core")]
mod backend_core {
    use crate::generation::prototypes::{
        ProtoBinaryGlweCiphertextView32, ProtoBinaryGlweCiphertextView64,
    };
    use crate::generation::synthesizing::SynthesizesGlweCiphertextView;
    use crate::generation::{Maker, Precision32, Precision64};
    use concrete_core::prelude::{
        DestructionEngine, GlweCiphertextCreationEngine, GlweCiphertextEntity,
        GlweCiphertextRetrievalEngine, GlweCiphertextView32, GlweCiphertextView64,
    };

    impl<'a> SynthesizesGlweCiphertextView<'a, Precision32, GlweCiphertextView32<'a>> for Maker {
        fn synthesize_glwe_ciphertext_view(
            &mut self,
            prototype: &Self::GlweCiphertextViewProto,
        ) -> GlweCiphertextView32<'a> {
            self.core_engine
                .create_glwe_ciphertext(
                    prototype.0.clone().leak() as &[u32],
                    prototype.1.to_owned(),
                )
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext_view(
            &mut self,
            entity: GlweCiphertextView32,
        ) -> Self::GlweCiphertextViewProto {
            let polynomial_size = entity.polynomial_size();
            let slice = self.core_engine.retrieve_glwe_ciphertext(entity).unwrap();
            ProtoBinaryGlweCiphertextView32(
                unsafe {
                    Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len())
                },
                polynomial_size,
            )
        }

        fn destroy_glwe_ciphertext_view(
            &mut self,
            entity: GlweCiphertextView32,
            drop_underlying_memory: bool,
        ) {
            // We don't know if this the last view referring to the slice it contains, so let the
            // programmer tell us if that's the case.
            if drop_underlying_memory {
                // If requested re-construct the vector so that it frees memory when it's dropped
                let slice = self.core_engine.retrieve_glwe_ciphertext(entity).unwrap();
                unsafe {
                    Vec::from_raw_parts(slice.as_ptr() as *mut u32, slice.len(), slice.len())
                };
            } else {
                self.core_engine.destroy(entity).unwrap();
            }
        }
    }

    impl<'a> SynthesizesGlweCiphertextView<'a, Precision64, GlweCiphertextView64<'a>> for Maker {
        fn synthesize_glwe_ciphertext_view(
            &mut self,
            prototype: &Self::GlweCiphertextViewProto,
        ) -> GlweCiphertextView64<'a> {
            self.core_engine
                .create_glwe_ciphertext(
                    prototype.0.clone().leak() as &[u64],
                    prototype.1.to_owned(),
                )
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext_view(
            &mut self,
            entity: GlweCiphertextView64,
        ) -> Self::GlweCiphertextViewProto {
            let polynomial_size = entity.polynomial_size();
            let slice = self.core_engine.retrieve_glwe_ciphertext(entity).unwrap();
            ProtoBinaryGlweCiphertextView64(
                unsafe {
                    Vec::from_raw_parts(slice.as_ptr() as *mut u64, slice.len(), slice.len())
                },
                polynomial_size,
            )
        }

        fn destroy_glwe_ciphertext_view(
            &mut self,
            entity: GlweCiphertextView64,
            drop_underlying_memory: bool,
        ) {
            // We don't know if this the last view referring to the slice it contains, so let the
            // programmer tell us if that's the case.
            if drop_underlying_memory {
                // If requested re-construct the vector so that it frees memory when it's dropped
                let slice = self.core_engine.retrieve_glwe_ciphertext(entity).unwrap();
                unsafe {
                    Vec::from_raw_parts(slice.as_ptr() as *mut u64, slice.len(), slice.len())
                };
            } else {
                self.core_engine.destroy(entity).unwrap();
            }
        }
    }

    use crate::generation::prototypes::{
        ProtoBinaryGlweCiphertextMutView32, ProtoBinaryGlweCiphertextMutView64,
    };
    use crate::generation::synthesizing::SynthesizesGlweCiphertextMutView;
    use concrete_core::prelude::{GlweCiphertextMutView32, GlweCiphertextMutView64};

    impl<'a> SynthesizesGlweCiphertextMutView<'a, Precision32, GlweCiphertextMutView32<'a>> for Maker {
        fn synthesize_glwe_ciphertext_mut_view(
            &mut self,
            prototype: &Self::GlweCiphertextMutViewProto,
        ) -> GlweCiphertextMutView32<'a> {
            self.core_engine
                .create_glwe_ciphertext(prototype.0.clone().leak(), prototype.1.to_owned())
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext_mut_view(
            &mut self,
            entity: GlweCiphertextMutView32,
        ) -> Self::GlweCiphertextMutViewProto {
            let polynomial_size = entity.polynomial_size();
            let slice = self.core_engine.retrieve_glwe_ciphertext(entity).unwrap();
            ProtoBinaryGlweCiphertextMutView32(
                unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) },
                polynomial_size,
            )
        }

        fn destroy_glwe_ciphertext_mut_view(&mut self, entity: GlweCiphertextMutView32) {
            // There should be only one mutable reference to memory, so re-construct the vector so
            // that it frees memory when it's dropped
            let slice = self.core_engine.retrieve_glwe_ciphertext(entity).unwrap();
            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }

    impl<'a> SynthesizesGlweCiphertextMutView<'a, Precision64, GlweCiphertextMutView64<'a>> for Maker {
        fn synthesize_glwe_ciphertext_mut_view(
            &mut self,
            prototype: &Self::GlweCiphertextMutViewProto,
        ) -> GlweCiphertextMutView64<'a> {
            self.core_engine
                .create_glwe_ciphertext(prototype.0.clone().leak(), prototype.1.to_owned())
                .unwrap()
        }

        fn unsynthesize_glwe_ciphertext_mut_view(
            &mut self,
            entity: GlweCiphertextMutView64,
        ) -> Self::GlweCiphertextMutViewProto {
            let polynomial_size = entity.polynomial_size();
            let slice = self.core_engine.retrieve_glwe_ciphertext(entity).unwrap();
            ProtoBinaryGlweCiphertextMutView64(
                unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) },
                polynomial_size,
            )
        }

        fn destroy_glwe_ciphertext_mut_view(&mut self, entity: GlweCiphertextMutView64) {
            // There should be only one mutable reference to memory, so re-construct the vector so
            // that it frees memory when it's dropped
            let slice = self.core_engine.retrieve_glwe_ciphertext(entity).unwrap();
            unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), slice.len(), slice.len()) };
        }
    }
}
