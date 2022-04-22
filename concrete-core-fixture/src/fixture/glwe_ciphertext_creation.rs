use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertextMutView, PrototypesGlweCiphertextView,
};
use crate::generation::synthesizing::{
    SynthesizesGlweCiphertextMutView, SynthesizesGlweCiphertextView,
};
use crate::generation::{IntegerPrecision, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

use concrete_core::prelude::{GlweCiphertextCreationEngine, GlweCiphertextEntity};

#[derive(Debug)]
pub struct GlweCiphertextViewCreationParameters {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
}

/// A fixture for the types implementing the `GlweCiphertextCreationEngine` trait with views.
pub struct GlweCiphertextViewCreationFixture;

impl<'a, Precision: 'a, Engine, GlweCiphertextView: 'a>
    Fixture<Precision, Engine, (GlweCiphertextView,)> for GlweCiphertextViewCreationFixture
where
    Precision: IntegerPrecision,
    Engine: GlweCiphertextCreationEngine<&'a [Precision::Raw], GlweCiphertextView>,
    GlweCiphertextView: GlweCiphertextEntity,
    Maker: SynthesizesGlweCiphertextView<'a, Precision, GlweCiphertextView>,
{
    type Parameters = GlweCiphertextViewCreationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (Vec<Precision::Raw>, PolynomialSize);
    type PreExecutionContext = (Vec<Precision::Raw>, PolynomialSize);
    type PostExecutionContext = (GlweCiphertextView,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextViewCreationParameters {
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(512),
                },
                GlweCiphertextViewCreationParameters {
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(1024),
                },
                GlweCiphertextViewCreationParameters {
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(2048),
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
        let Self::Parameters {
            glwe_dimension,
            polynomial_size,
        } = parameters;
        let num_elements = glwe_dimension.to_glwe_size().0 * polynomial_size.0;
        (Precision::Raw::uniform_vec(num_elements), *polynomial_size)
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
        let (underlying_container, polynomial_size) = context;
        // Highly unsafe with aliasing making borrowck lose its mind
        let slice_from_container: &[<Precision as IntegerPrecision>::Raw] =
            underlying_container.leak();
        let glwe_ciphertext_view = unsafe {
            engine.create_glwe_ciphertext_unchecked(slice_from_container, polynomial_size)
        };
        (glwe_ciphertext_view,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (glwe_ciphertext_view,) = context;
        // Unsynthesizing consumes the ciphertext view, no need to destroy it here
        let ciphertext_view_proto = maker.unsynthesize_glwe_ciphertext_view(glwe_ciphertext_view);
        (
            sample_proto.0.to_owned(),
            maker
                .transform_ciphertext_view_to_raw(&ciphertext_view_proto)
                .0,
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

/// A fixture for the types implementing the `GlweCiphertextCreationEngine` trait with mutable
/// views.
pub struct GlweCiphertextMutViewCreationFixture;

impl<'data, Precision: 'data, Engine, GlweCiphertextMutView: 'data>
    Fixture<Precision, Engine, (GlweCiphertextMutView,)> for GlweCiphertextMutViewCreationFixture
where
    Precision: IntegerPrecision,
    Engine: GlweCiphertextCreationEngine<&'data mut [Precision::Raw], GlweCiphertextMutView>,
    GlweCiphertextMutView: GlweCiphertextEntity,
    Maker: SynthesizesGlweCiphertextMutView<'data, Precision, GlweCiphertextMutView>,
{
    type Parameters = GlweCiphertextViewCreationParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes = (Vec<Precision::Raw>, PolynomialSize);
    type PreExecutionContext = (Vec<Precision::Raw>, PolynomialSize);
    type PostExecutionContext = (GlweCiphertextMutView,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextViewCreationParameters {
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(512),
                },
                GlweCiphertextViewCreationParameters {
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(1024),
                },
                GlweCiphertextViewCreationParameters {
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(2048),
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
        let Self::Parameters {
            glwe_dimension,
            polynomial_size,
        } = parameters;
        let num_elements = glwe_dimension.to_glwe_size().0 * polynomial_size.0;
        (Precision::Raw::uniform_vec(num_elements), *polynomial_size)
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
        let (underlying_container, polynomial_size) = context;
        // Highly unsafe with aliasing making borrowck lose its mind
        let slice_from_container = underlying_container.leak();
        let glwe_ciphertext_view = unsafe {
            engine.create_glwe_ciphertext_unchecked(slice_from_container, polynomial_size)
        };
        (glwe_ciphertext_view,)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (glwe_ciphertext_view,) = context;
        // Unsynthesizing consumes the ciphertext view, no need to destroy it here
        let ciphertext_view_proto =
            maker.unsynthesize_glwe_ciphertext_mut_view(glwe_ciphertext_view);
        (
            sample_proto.0.to_owned(),
            maker
                .transform_ciphertext_mut_view_to_raw(&ciphertext_view_proto)
                .0,
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
