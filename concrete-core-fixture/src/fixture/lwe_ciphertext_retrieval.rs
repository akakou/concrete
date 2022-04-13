use crate::fixture::Fixture;
use crate::generation::prototyping::{PrototypesLweCiphertextMutView, PrototypesLweCiphertextView};
use crate::generation::synthesizing::{
    SynthesizesLweCiphertextMutView, SynthesizesLweCiphertextView,
};
use crate::generation::{IntegerPrecision, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::LweDimension;

use concrete_core::prelude::{LweCiphertextEntity, LweCiphertextRetrievalEngine};

#[derive(Debug)]
pub struct LweCiphertextViewRetrievalParameters {
    pub lwe_dimension: LweDimension,
}

/// A fixture for the types implementing the `LweCiphertextRetrievalEngine` trait with views.
pub struct LweCiphertextViewRetrievalFixture;

impl<'a, Precision: 'a, Engine, LweCiphertextView: 'a>
    Fixture<Precision, Engine, (LweCiphertextView,)> for LweCiphertextViewRetrievalFixture
where
    Precision: IntegerPrecision,
    Engine: LweCiphertextRetrievalEngine<LweCiphertextView, &'a [Precision::Raw]>,
    LweCiphertextView: LweCiphertextEntity,
    Maker: SynthesizesLweCiphertextView<'a, Precision, LweCiphertextView>,
{
    type Parameters = LweCiphertextViewRetrievalParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes =
        (<Maker as PrototypesLweCiphertextView<Precision>>::LweCiphertextViewProto,);
    type PreExecutionContext = (LweCiphertextView,);
    type PostExecutionContext = (Vec<Precision::Raw>,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextViewRetrievalParameters {
                    lwe_dimension: LweDimension(1),
                },
                LweCiphertextViewRetrievalParameters {
                    lwe_dimension: LweDimension(512),
                },
                LweCiphertextViewRetrievalParameters {
                    lwe_dimension: LweDimension(751),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let num_elements = parameters.lwe_dimension.to_lwe_size().0;
        let proto_ciphertext_view =
            maker.transform_raw_to_ciphertext_view(Precision::Raw::uniform_vec(num_elements));
        (proto_ciphertext_view,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_ciphertext_view,) = sample_proto;
        (maker.synthesize_lwe_ciphertext_view(proto_ciphertext_view),)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (ciphertext_view,) = context;
        // Retrieval consumes a ciphertext view
        let raw_ciphertext = unsafe {
            engine
                .retrieve_lwe_ciphertext_unchecked(ciphertext_view)
                .to_vec()
        };
        (raw_ciphertext,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_ciphertext_view,) = sample_proto;
        let (raw_ciphertext,) = context;
        (
            maker.transform_ciphertext_view_to_raw(proto_ciphertext_view),
            raw_ciphertext,
        )
    }

    fn compute_criteria(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        (Variance(0.),)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        assert_noise_distribution(actual.as_slice(), means.as_slice(), criteria.0)
    }
}

/// A fixture for the types implementing the `LweCiphertextRetrievalEngine` trait with mut views.
pub struct LweCiphertextMutViewRetrievalFixture;

impl<'a, Precision: 'a, Engine, LweCiphertextMutView: 'a>
    Fixture<Precision, Engine, (LweCiphertextMutView,)> for LweCiphertextMutViewRetrievalFixture
where
    Precision: IntegerPrecision,
    Engine: LweCiphertextRetrievalEngine<LweCiphertextMutView, &'a mut [Precision::Raw]>,
    LweCiphertextMutView: LweCiphertextEntity,
    Maker: SynthesizesLweCiphertextMutView<'a, Precision, LweCiphertextMutView>,
{
    type Parameters = LweCiphertextViewRetrievalParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes =
        (<Maker as PrototypesLweCiphertextMutView<Precision>>::LweCiphertextMutViewProto,);
    type PreExecutionContext = (LweCiphertextMutView,);
    type PostExecutionContext = (Vec<Precision::Raw>,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextViewRetrievalParameters {
                    lwe_dimension: LweDimension(1),
                },
                LweCiphertextViewRetrievalParameters {
                    lwe_dimension: LweDimension(512),
                },
                LweCiphertextViewRetrievalParameters {
                    lwe_dimension: LweDimension(751),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let num_elements = parameters.lwe_dimension.to_lwe_size().0;
        let proto_ciphertext_mut_view =
            maker.transform_raw_to_ciphertext_mut_view(Precision::Raw::uniform_vec(num_elements));
        (proto_ciphertext_mut_view,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_ciphertext_mut_view,) = sample_proto;
        (maker.synthesize_lwe_ciphertext_mut_view(proto_ciphertext_mut_view),)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (ciphertext_mut_view,) = context;
        // Retrieval consumes a ciphertext mut view
        let raw_ciphertext = unsafe {
            engine
                .retrieve_lwe_ciphertext_unchecked(ciphertext_mut_view)
                .to_vec()
        };
        (raw_ciphertext,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_ciphertext_mut_view,) = sample_proto;
        let (raw_ciphertext,) = context;
        (
            maker.transform_ciphertext_mut_view_to_raw(proto_ciphertext_mut_view),
            raw_ciphertext,
        )
    }

    fn compute_criteria(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        (Variance(0.),)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        assert_noise_distribution(actual.as_slice(), means.as_slice(), criteria.0)
    }
}
