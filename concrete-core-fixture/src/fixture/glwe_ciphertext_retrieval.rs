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

use concrete_core::prelude::{GlweCiphertextEntity, GlweCiphertextRetrievalEngine};

#[derive(Debug)]
pub struct GlweCiphertextViewRetrievalParameters {
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
}

/// A fixture for the types implementing the `GlweCiphertextRetrievalEngine` trait with views.
pub struct GlweCiphertextViewRetrievalFixture;

impl<'a, Precision: 'a, Engine, GlweCiphertextView: 'a>
    Fixture<Precision, Engine, (GlweCiphertextView,)> for GlweCiphertextViewRetrievalFixture
where
    Precision: IntegerPrecision,
    Engine: GlweCiphertextRetrievalEngine<GlweCiphertextView, &'a [Precision::Raw]>,
    GlweCiphertextView: GlweCiphertextEntity,
    Maker: SynthesizesGlweCiphertextView<'a, Precision, GlweCiphertextView>,
{
    type Parameters = GlweCiphertextViewRetrievalParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes =
        (<Maker as PrototypesGlweCiphertextView<Precision>>::GlweCiphertextViewProto,);
    type PreExecutionContext = (GlweCiphertextView,);
    type PostExecutionContext = (Vec<Precision::Raw>,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextViewRetrievalParameters {
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(512),
                },
                GlweCiphertextViewRetrievalParameters {
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(1024),
                },
                GlweCiphertextViewRetrievalParameters {
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
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let Self::Parameters {
            glwe_dimension,
            polynomial_size,
        } = parameters;
        let num_elements = glwe_dimension.to_glwe_size().0 * polynomial_size.0;
        let proto_ciphertext_view = maker.transform_raw_to_ciphertext_view(
            Precision::Raw::uniform_vec(num_elements),
            *polynomial_size,
        );
        (proto_ciphertext_view,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_ciphertext_view,) = sample_proto;
        (maker.synthesize_glwe_ciphertext_view(proto_ciphertext_view),)
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
                .retrieve_glwe_ciphertext_unchecked(ciphertext_view)
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
            maker
                .transform_ciphertext_view_to_raw(proto_ciphertext_view)
                .0,
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

/// A fixture for the types implementing the `GlweCiphertextRetrievalEngine` trait with mut views.
pub struct GlweCiphertextMutViewRetrievalFixture;

impl<'a, Precision: 'a, Engine, GlweCiphertextMutView: 'a>
    Fixture<Precision, Engine, (GlweCiphertextMutView,)> for GlweCiphertextMutViewRetrievalFixture
where
    Precision: IntegerPrecision,
    Engine: GlweCiphertextRetrievalEngine<GlweCiphertextMutView, &'a mut [Precision::Raw]>,
    GlweCiphertextMutView: GlweCiphertextEntity,
    Maker: SynthesizesGlweCiphertextMutView<'a, Precision, GlweCiphertextMutView>,
{
    type Parameters = GlweCiphertextViewRetrievalParameters;
    type RepetitionPrototypes = ();
    type SamplePrototypes =
        (<Maker as PrototypesGlweCiphertextMutView<Precision>>::GlweCiphertextMutViewProto,);
    type PreExecutionContext = (GlweCiphertextMutView,);
    type PostExecutionContext = (Vec<Precision::Raw>,);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextViewRetrievalParameters {
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(512),
                },
                GlweCiphertextViewRetrievalParameters {
                    glwe_dimension: GlweDimension(2),
                    polynomial_size: PolynomialSize(1024),
                },
                GlweCiphertextViewRetrievalParameters {
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
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let Self::Parameters {
            glwe_dimension,
            polynomial_size,
        } = parameters;
        let num_elements = glwe_dimension.to_glwe_size().0 * polynomial_size.0;
        let proto_ciphertext_mut_view = maker.transform_raw_to_ciphertext_mut_view(
            Precision::Raw::uniform_vec(num_elements),
            *polynomial_size,
        );
        (proto_ciphertext_mut_view,)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (proto_ciphertext_mut_view,) = sample_proto;
        (maker.synthesize_glwe_ciphertext_mut_view(proto_ciphertext_mut_view),)
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
                .retrieve_glwe_ciphertext_unchecked(ciphertext_mut_view)
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
            maker
                .transform_ciphertext_mut_view_to_raw(proto_ciphertext_mut_view)
                .0,
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
