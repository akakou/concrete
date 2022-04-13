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

use concrete_core::prelude::{LweCiphertextCreationEngine, LweCiphertextEntity};

#[derive(Debug)]
pub struct LweCiphertextViewCreationParameters {
    pub lwe_dimension: LweDimension,
}

/// A fixture for the types implementing the `LweCiphertextCreationEngine` trait with views.
pub struct LweCiphertextViewCreationFixture;

impl<'a, Precision: 'a, Engine, LweCiphertextView: 'a>
    Fixture<Precision, Engine, (LweCiphertextView,)> for LweCiphertextViewCreationFixture
where
    Precision: IntegerPrecision,
    Engine: LweCiphertextCreationEngine<&'a [Precision::Raw], LweCiphertextView>,
    LweCiphertextView: LweCiphertextEntity,
    Maker: SynthesizesLweCiphertextView<'a, Precision, LweCiphertextView>,
{
    type Parameters = LweCiphertextViewCreationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (Vec<Precision::Raw>,);
    type PreExecutionContext = (Vec<Precision::Raw>,);
    type PostExecutionContext = (LweCiphertextView,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextViewCreationParameters {
                    lwe_dimension: LweDimension(1),
                },
                LweCiphertextViewCreationParameters {
                    lwe_dimension: LweDimension(512),
                },
                LweCiphertextViewCreationParameters {
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
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let num_elements = parameters.lwe_dimension.to_lwe_size().0;
        (Precision::Raw::uniform_vec(num_elements),)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        sample_proto.to_owned()
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (underlying_container,) = context;
        // Highly unsafe with aliasing making borrowck lose its mind
        let slice_from_container: &[<Precision as IntegerPrecision>::Raw] =
            underlying_container.leak();
        let lwe_ciphertext_view =
            unsafe { engine.create_lwe_ciphertext_unchecked(slice_from_container) };
        (lwe_ciphertext_view,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (lwe_ciphertext_view,) = context;
        // Unsynthesizing consumes the ciphertext view, no need to destroy it here
        let ciphertext_view_proto = maker.unsynthesize_lwe_ciphertext_view(lwe_ciphertext_view);
        (
            sample_proto.0.to_owned(),
            maker.transform_ciphertext_view_to_raw(&ciphertext_view_proto),
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

/// A fixture for the types implementing the `LweCiphertextCreationEngine` trait with mutable views.
pub struct LweCiphertextMutViewCreationFixture;

impl<'data, Precision: 'data, Engine, LweCiphertextMutView: 'data>
    Fixture<Precision, Engine, (LweCiphertextMutView,)> for LweCiphertextMutViewCreationFixture
where
    Precision: IntegerPrecision,
    Engine: LweCiphertextCreationEngine<&'data mut [Precision::Raw], LweCiphertextMutView>,
    LweCiphertextMutView: LweCiphertextEntity,
    Maker: SynthesizesLweCiphertextMutView<'data, Precision, LweCiphertextMutView>,
{
    type Parameters = LweCiphertextViewCreationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (Vec<Precision::Raw>,);
    type PreExecutionContext = (Vec<Precision::Raw>,);
    type PostExecutionContext = (LweCiphertextMutView,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextViewCreationParameters {
                    lwe_dimension: LweDimension(1),
                },
                LweCiphertextViewCreationParameters {
                    lwe_dimension: LweDimension(512),
                },
                LweCiphertextViewCreationParameters {
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
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let num_elements = parameters.lwe_dimension.to_lwe_size().0;
        (Precision::Raw::uniform_vec(num_elements),)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        sample_proto.to_owned()
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (underlying_container,) = context;
        // Highly unsafe with aliasing making borrowck lose its mind
        let slice_from_container = underlying_container.leak();
        let lwe_ciphertext_view =
            unsafe { engine.create_lwe_ciphertext_unchecked(slice_from_container) };
        (lwe_ciphertext_view,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (lwe_ciphertext_view,) = context;
        // Unsynthesizing consumes the ciphertext view, no need to destroy it here
        let ciphertext_view_proto = maker.unsynthesize_lwe_ciphertext_mut_view(lwe_ciphertext_view);
        (
            sample_proto.0.to_owned(),
            maker.transform_ciphertext_mut_view_to_raw(&ciphertext_view_proto),
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
