/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.utils.GqGroupMemberGenerator;

@DisplayName("A ciphertext")
class ElGamalMultiRecipientCiphertextTest {

	private static GqGroup group;
	private static GqGroupMemberGenerator generator;

	private static ImmutableList<GqElement> validPhis;
	private static GqElement validGamma;

	@BeforeAll
	static void setUpAll() {
		// Group setup.
		final BigInteger p = new BigInteger("23");
		final BigInteger q = new BigInteger("11");
		final BigInteger g = new BigInteger("2");

		group = new GqGroup(p, q, g);
		generator = new GqGroupMemberGenerator(group);
	}

	@BeforeEach
	void setUp() {
		// Generate valid phis.
		final GqElement ge1 = generator.genGqElementMember();
		final GqElement ge2 = generator.genGqElementMember();

		validPhis = ImmutableList.of(ge1, ge2);

		// Generate a valid gamma.
		do {
			validGamma = generator.genNonIdentityGqElementMember();
		} while (validGamma.equals(group.getGenerator()));
	}

	@Test
	@DisplayName("contains the correct gamma and phis")
	void constructionTest() {
		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);

		assertEquals(validGamma, ciphertext.getGamma());
		assertEquals(validPhis, ciphertext.getPhis());
	}

	// Provides parameters for the withInvalidParameters test.
	static Stream<Arguments> createArgumentsProvider() {

		final GqElement gammaOne = GqElement.create(BigInteger.ONE, group);
		final GqElement gammaGenerator = group.getGenerator();
		final List<GqElement> invalidPhis = Arrays.asList(GqElement.create(BigInteger.ONE, group), null);

		final GqGroup differentGroup = new GqGroup(BigInteger.valueOf(7), BigInteger.valueOf(3), BigInteger.valueOf(2));
		final GqGroupMemberGenerator differentGenerator = new GqGroupMemberGenerator(differentGroup);
		final List<GqElement> differentGroupPhis = Arrays.asList(generator.genGqElementMember(), differentGenerator.genGqElementMember());

		final GqElement otherGroupGamma = genOtherGroupGamma(differentGroup);

		return Stream.of(
				Arguments.of(null, validPhis, NullPointerException.class),
				Arguments.of(gammaOne, validPhis, IllegalArgumentException.class),
				Arguments.of(gammaGenerator, validPhis, IllegalArgumentException.class),
				Arguments.of(validGamma, null, NullPointerException.class),
				Arguments.of(validGamma, Collections.emptyList(), IllegalArgumentException.class),
				Arguments.of(validGamma, invalidPhis, IllegalArgumentException.class),
				Arguments.of(validGamma, differentGroupPhis, IllegalArgumentException.class),
				Arguments.of(otherGroupGamma, validPhis, IllegalArgumentException.class)
		);
	}

	@ParameterizedTest(name = "gamma = {0} and phis = {1} throws {2}")
	@MethodSource("createArgumentsProvider")
	@DisplayName("created with invalid parameters")
	void withInvalidParameters(final GqElement gamma, final List<GqElement> phis, final Class<? extends RuntimeException> exceptionClass) {
		assertThrows(exceptionClass, () -> ElGamalMultiRecipientCiphertext.create(gamma, phis));
	}

	@Test
	@DisplayName("has valid equals for gamma")
	void gammaEqualsTest() {
		final GqElement differentGamma = genDifferentGamma();

		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext sameCiphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext differentCiphertext = ElGamalMultiRecipientCiphertext.create(differentGamma, validPhis);

		assertEquals(ciphertext, sameCiphertext);
		assertNotEquals(ciphertext, differentCiphertext);
	}

	@Test
	@DisplayName("has valid equals for the phis")
	void phisEqualsTest() {
		final List<GqElement> differentPhis = genDifferentPhis();

		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext sameCiphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext differentCiphertext = ElGamalMultiRecipientCiphertext.create(validGamma, differentPhis);

		assertEquals(ciphertext, sameCiphertext);
		assertNotEquals(ciphertext, differentCiphertext);
	}

	@Test
	@DisplayName("has valid hashCode")
	void hashCodeTest() {
		final GqElement differentGamma = genDifferentGamma();

		final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext sameCiphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);
		final ElGamalMultiRecipientCiphertext differentCiphertext = ElGamalMultiRecipientCiphertext.create(differentGamma, validPhis);

		assertEquals(ciphertext.hashCode(), sameCiphertext.hashCode());
		assertNotEquals(ciphertext.hashCode(), differentCiphertext.hashCode());
	}

	private static GqElement genOtherGroupGamma(final GqGroup otherGroup) {
		final GqGroupMemberGenerator otherGroupGenerator = new GqGroupMemberGenerator(otherGroup);

		GqElement otherGroupGamma;
		do {
			otherGroupGamma = otherGroupGenerator.genNonIdentityGqElementMember();
		} while (otherGroupGamma.equals(otherGroup.getGenerator()));
		return otherGroupGamma;
	}

	private GqElement genDifferentGamma() {
		GqElement differentGamma;
		do {
			differentGamma = generator.genNonIdentityGqElementMember();
		} while (differentGamma.equals(validGamma) || differentGamma.equals(group.getGenerator()));
		return differentGamma;
	}

	private List<GqElement> genDifferentPhis() {
		List<GqElement> differentPhis;
		do {
			differentPhis = Arrays.asList(generator.genGqElementMember(), generator.genGqElementMember());
		} while (differentPhis.equals(validPhis));
		return differentPhis;
	}

	private List<GqElement> genOtherGroupPhis(final GqGroup otherGroup) {
		final GqGroupMemberGenerator otherGroupGenerator = new GqGroupMemberGenerator(otherGroup);

		return Arrays.asList(otherGroupGenerator.genGqElementMember(), otherGroupGenerator.genGqElementMember());
	}

	@Nested
	@DisplayName("multiplied")
	class WhenMultiplying {

		// All the input/output values should later be read from a json file.
		@Test
		@DisplayName("with a valid other ciphertext gives expected result")
		void multiplyTest() {
			final GqGroup group = new GqGroup(BigInteger.valueOf(11), BigInteger.valueOf(5), BigInteger.valueOf(3));

			// Create first ciphertext.
			final GqElement gammaA = GqElement.create(BigInteger.valueOf(4), group);
			final List<GqElement> phisA = Arrays
					.asList(GqElement.create(BigInteger.valueOf(3), group), GqElement.create(BigInteger.valueOf(5), group));
			final ElGamalMultiRecipientCiphertext ciphertextA = ElGamalMultiRecipientCiphertext.create(gammaA, phisA);

			// Create second ciphertext.
			final GqElement gammaB = GqElement.create(BigInteger.valueOf(5), group);
			final List<GqElement> phisB = Arrays
					.asList(GqElement.create(BigInteger.valueOf(9), group), GqElement.create(BigInteger.valueOf(1), group));
			final ElGamalMultiRecipientCiphertext ciphertextB = ElGamalMultiRecipientCiphertext.create(gammaB, phisB);

			// Expected multiplication result.
			final GqElement gammaRes = GqElement.create(BigInteger.valueOf(9), group);
			final List<GqElement> phisRes = Arrays.asList(GqElement.create(BigInteger.valueOf(5), group), GqElement.create(BigInteger.valueOf(5),
					group));
			final ElGamalMultiRecipientCiphertext ciphertextRes = ElGamalMultiRecipientCiphertext.create(gammaRes, phisRes);

			assertEquals(ciphertextRes, ciphertextA.multiply(ciphertextB));
		}

		@Test
		@DisplayName("with a null ciphertext throws NullPointerException")
		void multiplyWithNullOtherShouldThrow() {
			final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);

			assertThrows(NullPointerException.class, () -> ciphertext.multiply(null));
		}

		@Test
		@DisplayName("with a ciphertext from another group throws IllegalArgumentException")
		void multiplyWithDifferentGroupOtherShouldThrow() {
			final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);

			final GqGroup otherGroup = new GqGroup(BigInteger.valueOf(7), BigInteger.valueOf(3), BigInteger.valueOf(2));
			final GqElement otherGroupGamma = genOtherGroupGamma(otherGroup);
			final List<GqElement> otherGroupPhis = genOtherGroupPhis(otherGroup);
			final ElGamalMultiRecipientCiphertext other = ElGamalMultiRecipientCiphertext.create(otherGroupGamma, otherGroupPhis);

			assertThrows(IllegalArgumentException.class, () -> ciphertext.multiply(other));
		}

		@Test
		@DisplayName("with a ciphertext with a different number of phis throws IllegalArgumentException")
		void multiplyWithDifferentSizePhisShouldThrow() {
			final ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(validGamma, validPhis);

			final ImmutableList<GqElement> differentSizePhis = ImmutableList.of(validPhis.get(0));
			final ElGamalMultiRecipientCiphertext other = ElGamalMultiRecipientCiphertext.create(validGamma, differentSizePhis);

			assertThrows(IllegalArgumentException.class, () -> ciphertext.multiply(other));
		}

	}

}
