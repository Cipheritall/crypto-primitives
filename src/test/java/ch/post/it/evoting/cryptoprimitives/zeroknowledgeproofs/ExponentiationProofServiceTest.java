/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;

import ch.post.it.evoting.cryptoprimitives.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

class ExponentiationProofServiceTest extends TestGroupSetup {

	private static final int MAX_NUMBER_EXPONENTIATIONS = 10;
	private static RandomService randomService;
	private static HashService hashService;
	private static ZeroKnowledgeProof proofService;

	@BeforeAll
	static void setupAll() {
		randomService = new RandomService();
		hashService = TestHashService.create(gqGroup.getQ());
		proofService = new ZeroKnowledgeProofService(randomService, hashService);
	}

	@Test
	void constructorNotNullChecks() {
		assertThrows(NullPointerException.class, () -> new ExponentiationProofService(null, hashService));
		assertThrows(NullPointerException.class, () -> new ExponentiationProofService(randomService, null));
	}

	private static class TestValues {
		private final BigInteger p = BigInteger.valueOf(11);
		private final BigInteger q = BigInteger.valueOf(5);
		private final BigInteger g = BigInteger.valueOf(3);
		private final GqGroup gqGroup = new GqGroup(p, q, g);
		private final ZqGroup zqGroup = new ZqGroup(q);

		private final GqElement gThree = GqElementFactory.fromValue(BigInteger.valueOf(3), gqGroup);
		private final GqElement gFour = GqElementFactory.fromValue(BigInteger.valueOf(4), gqGroup);
		private final GqElement gFive = GqElementFactory.fromValue(BigInteger.valueOf(5), gqGroup);
		private final GqElement gNine = GqElementFactory.fromValue(BigInteger.valueOf(9), gqGroup);

		private final ZqElement zOne = ZqElement.create(BigInteger.ONE, zqGroup);
		private final ZqElement zTwo = ZqElement.create(BigInteger.valueOf(2), zqGroup);
		private final ZqElement zThree = ZqElement.create(BigInteger.valueOf(3), zqGroup);

		// Input arguments:
		// bases = (4, 3)
		// exponent = 3
		// exponentiations = (9, 5)
		// auxiliaryInformation = ("specific", "test", "values")
		private final GroupVector<GqElement, GqGroup> bases = GroupVector.of(gFour, gThree);
		private final ZqElement exponent = zThree;
		private final GroupVector<GqElement, GqGroup> exponentiations = GroupVector.of(gNine, gFive);
		private final List<String> auxiliaryInformation = Arrays.asList("specific", "test", "values");

		// Output:
		// e = 2
		// z = 3
		private final ZqElement e = zTwo;
		private final ZqElement z = zThree;

		private final List<BigInteger> randomValues = Collections.singletonList(BigInteger.valueOf(2));

		private RandomService getSpecificRandomService() {
			return new RandomService() {
				final Iterator<BigInteger> values = randomValues.iterator();

				@Override
				public BigInteger genRandomInteger(BigInteger upperBound) {
					return values.next();
				}
			};
		}

		private ExponentiationProofService createExponentiationProofService() {
			final RandomService randomService = getSpecificRandomService();
			final HashService hashService = TestHashService.create(q);
			return new ExponentiationProofService(randomService, hashService);
		}

		private ExponentiationProof createExponentiationProof() {
			return new ExponentiationProof(e, z);
		}
	}

	@Nested
	class ComputePhiExponentiationTest {
		private ZqElement preimage;
		private GroupVector<GqElement, GqGroup> bases;

		@BeforeEach
		void setup() {
			final int n = secureRandom.nextInt(10) + 1;
			preimage = zqGroupGenerator.genRandomZqElementMember();
			bases = gqGroupGenerator.genRandomGqElementVector(n);
		}

		@Test
		void notNullChecks() {
			assertThrows(NullPointerException.class, () -> ExponentiationProofService.computePhiExponentiation(null, bases));
			assertThrows(NullPointerException.class, () -> ExponentiationProofService.computePhiExponentiation(preimage, null));
		}

		@Test
		void basesNotEmptyCheck() {
			final GroupVector<GqElement, GqGroup> emptyBases = GroupVector.of();
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> ExponentiationProofService.computePhiExponentiation(preimage, emptyBases));
			assertEquals("The vector of bases must contain at least 1 element.", exception.getMessage());
		}

		@Test
		void sameGroupOrderCheck() {
			final ZqElement otherpreimage = otherZqGroupGenerator.genRandomZqElementMember();
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> ExponentiationProofService.computePhiExponentiation(otherpreimage, bases));
			assertEquals("The preimage and the bases must have the same group order.", exception.getMessage());
		}

		@RepeatedTest(10)
		void phiFunctionSize() {
			assertEquals(bases.size(), ExponentiationProofService.computePhiExponentiation(preimage, bases).size());
		}

		@Test
		void withSpecificValues() {
			final GqGroup gqGroup = GroupTestData.getGroupP59();
			final ZqElement preimage = ZqElement.create(3, ZqGroup.sameOrderAs(gqGroup));
			final GroupVector<GqElement, GqGroup> bases = GroupVector.of(GqElementFactory.fromValue(BigInteger.ONE, gqGroup),
					GqElementFactory.fromValue(BigInteger.valueOf(4), gqGroup),
					GqElementFactory.fromValue(BigInteger.valueOf(9), gqGroup));

			final GroupVector<GqElement, GqGroup> expected = GroupVector.of(GqElementFactory.fromValue(BigInteger.ONE, gqGroup),
					GqElementFactory.fromValue(BigInteger.valueOf(5), gqGroup),
					GqElementFactory.fromValue(BigInteger.valueOf(21), gqGroup));
			assertEquals(expected, ExponentiationProofService.computePhiExponentiation(preimage, bases));
		}
	}

	@Nested
	class GenExponentiationProofTest {

		private final List<String> auxiliaryInformation = Arrays.asList("aux", "1");
		private int n;
		private GroupVector<GqElement, GqGroup> bases;
		private ZqElement exponent;
		private GroupVector<GqElement, GqGroup> exponentiations;

		@BeforeEach
		void setup() {
			n = secureRandom.nextInt(MAX_NUMBER_EXPONENTIATIONS) + 1;
			bases = gqGroupGenerator.genRandomGqElementVector(n);
			exponent = zqGroupGenerator.genRandomZqElementMember();
			exponentiations = ExponentiationProofService.computePhiExponentiation(exponent, bases);
		}

		@Test
		void notNullChecks() {
			assertThrows(NullPointerException.class,
					() -> proofService.genExponentiationProof(null, exponent, exponentiations, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> proofService.genExponentiationProof(bases, null, exponentiations, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> proofService.genExponentiationProof(bases, exponent, null, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> proofService.genExponentiationProof(bases, exponent, exponentiations, null));
		}

		@Test
		void validArguments() {
			assertDoesNotThrow(() -> proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation));
			assertDoesNotThrow(() -> proofService.genExponentiationProof(bases, exponent, exponentiations, Collections.emptyList()));
		}

		@Test
		void hashLengthCheck() {
			final ExponentiationProofService badService = new ExponentiationProofService(randomService, HashService.getInstance());
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> badService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation));
			assertEquals("The hash service's bit length must be smaller than the bit length of q.", exception.getMessage());
		}

		@Test
		void auxiliaryInformationDoesNotContainNullCheck() {
			final List<String> auxiliaryInformationWithNull = Arrays.asList("test", null);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformationWithNull));
			assertEquals("The auxiliary information must not contain null objects.", exception.getMessage());
		}

		@Test
		void basesNotEmptyCheck() {
			final GroupVector<GqElement, GqGroup> emptyBases = GroupVector.of();
			IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.genExponentiationProof(emptyBases, exponent, exponentiations, auxiliaryInformation));
			assertEquals("The bases must contain at least 1 element.", exception.getMessage());
		}

		@Test
		void basesAndExponentiationsSameSizeCheck() {
			bases = bases.append(gqGroupGenerator.genMember());
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation));
			assertEquals("Bases and exponentiations must have the same size.", exception.getMessage());
		}

		@Test
		void basesAndExponentiationsSameGroupCheck() {
			exponentiations = otherGqGroupGenerator.genRandomGqElementVector(n);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation));
			assertEquals("Bases and exponentiations must have the same group.", exception.getMessage());
		}

		@Test
		void exponentSameGroupOrderThanExponentiationsCheck() {
			exponent = otherZqGroupGenerator.genRandomZqElementMember();
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation));
			assertEquals("The exponent and the exponentiations must have the same group order.", exception.getMessage());
		}

		@Test
		void exponentiationsArePhiExponentiationCheck() {
			final GroupVector<GqElement, GqGroup> otherExponentiations = exponentiations.stream().map(exp -> exp.multiply(gqGroup.getGenerator()))
					.collect(toGroupVector());
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.genExponentiationProof(bases, exponent, otherExponentiations, auxiliaryInformation));
			assertEquals("The exponentiations must correspond to the exponent's and bases' phi exponentiation.", exception.getMessage());
		}

		@Test
		void specificValuesGiveExpectedResult() {
			final TestValues testValues = new TestValues();
			// Input.
			final GroupVector<GqElement, GqGroup> bases = testValues.bases;
			final ZqElement exponent = testValues.exponent;
			final GroupVector<GqElement, GqGroup> exponentiations = testValues.exponentiations;
			final List<String> auxiliaryInformation = testValues.auxiliaryInformation;

			final ExponentiationProofService proofService = testValues.createExponentiationProofService();

			final ExponentiationProof expected = testValues.createExponentiationProof();

			assertEquals(expected, proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation));
		}
	}

	@Nested
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VerifyExponentiationProofTest {

		private final List<String> auxiliaryInformation = Arrays.asList("aux", "2");
		private int n;
		private GroupVector<GqElement, GqGroup> bases;
		private GroupVector<GqElement, GqGroup> exponentiations;
		private ExponentiationProof proof;

		@BeforeEach
		void setup() {
			n = secureRandom.nextInt(MAX_NUMBER_EXPONENTIATIONS) + 1;
			bases = gqGroupGenerator.genRandomGqElementVector(n);
			exponentiations = gqGroupGenerator.genRandomGqElementVector(n);
			final ZqElement e = zqGroupGenerator.genRandomZqElementMember();
			final ZqElement z = zqGroupGenerator.genRandomZqElementMember();
			proof = new ExponentiationProof(e, z);
		}

		@Test
		void notNullChecks() {
			assertThrows(NullPointerException.class,
					() -> proofService.verifyExponentiation(null, exponentiations, proof, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> proofService.verifyExponentiation(bases, null, proof, auxiliaryInformation));
			assertThrows(NullPointerException.class,
					() -> proofService.verifyExponentiation(bases, exponentiations, null, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> proofService.verifyExponentiation(bases, exponentiations, proof, null));
		}

		@Test
		void hashLengthCheck() {
			final ExponentiationProofService badService = new ExponentiationProofService(randomService, HashService.getInstance());
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> badService.verifyExponentiation(bases, exponentiations, proof, auxiliaryInformation));
			assertEquals("The hash service's bit length must be smaller than the bit length of q.", exception.getMessage());
		}

		@Test
		void basesNotEmptyCheck() {
			final GroupVector<GqElement, GqGroup> emptyBases = GroupVector.of();
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.verifyExponentiation(emptyBases, exponentiations, proof, auxiliaryInformation));
			assertEquals("The bases must contain at least 1 element.", exception.getMessage());
		}

		@Test
		void basesAndExponentiationsSameSizeCheck() {
			final GroupVector<GqElement, GqGroup> tooLongBases = bases.append(gqGroupGenerator.genMember());
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.verifyExponentiation(tooLongBases, exponentiations, proof, auxiliaryInformation));
			assertEquals("Bases and exponentiations must have the same size.", exception.getMessage());
		}

		@Test
		void basesAndExponentiationsSameGroupCheck() {
			final GroupVector<GqElement, GqGroup> otherExponentiations = otherGqGroupGenerator.genRandomGqElementVector(n);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.verifyExponentiation(bases, otherExponentiations, proof, auxiliaryInformation));
			assertEquals("Bases and exponentiations must belong to the same group.", exception.getMessage());
		}

		@Test
		void proofSameGroupOrderAsBasesCheck() {
			final ZqElement otherE = otherZqGroupGenerator.genRandomZqElementMember();
			final ZqElement otherZ = otherZqGroupGenerator.genRandomZqElementMember();
			final ExponentiationProof otherProof = new ExponentiationProof(otherE, otherZ);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> proofService.verifyExponentiation(bases, exponentiations, otherProof, auxiliaryInformation));
			assertEquals("The proof must have the same group order as the bases.", exception.getMessage());
		}

		@Test
		void validProofReturnsTrue() {
			final ZqElement exponent = zqGroupGenerator.genRandomZqElementMember();
			exponentiations = ExponentiationProofService.computePhiExponentiation(exponent, bases);
			proof = proofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation);
			assertTrue(proofService.verifyExponentiation(bases, exponentiations, proof, auxiliaryInformation));

			proof = proofService.genExponentiationProof(bases, exponent, exponentiations, Collections.emptyList());
			assertTrue(proofService.verifyExponentiation(bases, exponentiations, proof, Collections.emptyList()));
		}

		@Test
		void differentAuxiliaryInformationReturnsFalse() {
			TestValues testValues = new TestValues();
			final GroupVector<GqElement, GqGroup> bases = testValues.bases;
			final GroupVector<GqElement, GqGroup> exponentiations = testValues.exponentiations;
			final List<String> auxiliaryInformation = testValues.auxiliaryInformation;
			auxiliaryInformation.set(0, "random");
			final ExponentiationProof proof = testValues.createExponentiationProof();
			final ExponentiationProofService proofService = testValues.createExponentiationProofService();
			assertFalse(proofService.verifyExponentiation(bases, exponentiations, proof, auxiliaryInformation));
		}

		@Test
		void invalidProofReturnsFalse() {
			TestValues testValues = new TestValues();
			final GroupVector<GqElement, GqGroup> bases = testValues.bases;
			final GroupVector<GqElement, GqGroup> exponentiations = testValues.exponentiations;
			final List<String> auxiliaryInformation = testValues.auxiliaryInformation;
			final ExponentiationProof proof = testValues.createExponentiationProof();
			final ZqElement e_prime = proof.get_e().add(testValues.zThree);
			final ExponentiationProof invalidProof = new ExponentiationProof(e_prime, proof.get_z());
			final ExponentiationProofService proofService = testValues.createExponentiationProofService();
			assertFalse(proofService.verifyExponentiation(bases, exponentiations, invalidProof, auxiliaryInformation));
		}

		@Test
		void differentEponentiationsReturnsFalse() {
			TestValues testValues = new TestValues();
			final GroupVector<GqElement, GqGroup> bases = testValues.bases;
			final GroupVector<GqElement, GqGroup> exponentiations = testValues.exponentiations;
			final GroupVector<GqElement, GqGroup> differentExponentiations = exponentiations.stream().map(y -> y.multiply(testValues.gNine))
					.collect(GroupVector.toGroupVector());
			final List<String> auxiliaryInformation = testValues.auxiliaryInformation;
			final ExponentiationProof proof = testValues.createExponentiationProof();
			final ExponentiationProofService proofService = testValues.createExponentiationProofService();
			assertFalse(proofService.verifyExponentiation(bases, differentExponentiations, proof, auxiliaryInformation));
		}

		@Test
		void differentBasesReturnsFalse() {
			TestValues testValues = new TestValues();
			final GroupVector<GqElement, GqGroup> bases = testValues.bases;
			final GroupVector<GqElement, GqGroup> differentBases = bases.stream().map(g -> g.multiply(testValues.gFour))
					.collect(GroupVector.toGroupVector());
			final GroupVector<GqElement, GqGroup> exponentiations = testValues.exponentiations;
			final List<String> auxiliaryInformation = testValues.auxiliaryInformation;
			final ExponentiationProof proof = testValues.createExponentiationProof();
			final ExponentiationProofService proofService = testValues.createExponentiationProofService();
			assertFalse(proofService.verifyExponentiation(differentBases, exponentiations, proof, auxiliaryInformation));
		}

		private Stream<Arguments> jsonFileArgumentProvider() {
			final List<TestParameters> parametersList = TestParameters.fromResource("/zeroknowledgeproofs/verify-exponentiation.json");

			return parametersList.stream().parallel().map(testParameters -> {
				// Context.
				final JsonData context = testParameters.getContext();
				final BigInteger p = context.get("p", BigInteger.class);
				final BigInteger q = context.get("q", BigInteger.class);
				final BigInteger g = context.get("g", BigInteger.class);

				try (MockedStatic<SecurityLevelConfig> mockedSecurityLevel = mockStatic(SecurityLevelConfig.class)) {
					mockedSecurityLevel.when(SecurityLevelConfig::getSystemSecurityLevel).thenReturn(testParameters.getSecurityLevel());
					final GqGroup gqGroup = new GqGroup(p, q, g);
					final ZqGroup zqGroup = new ZqGroup(q);

					final JsonData input = testParameters.getInput();

					// Parse bases parameters.

					final BigInteger[] basesArray = input.get("bases", BigInteger[].class);
					final GroupVector<GqElement, GqGroup> bases = Arrays.stream(basesArray).map(basesA -> GqElementFactory.fromValue(basesA, gqGroup))
							.collect(toGroupVector());

					// Parse exponentiations parameters
					final BigInteger[] exponentiationsArray = input.get("statement", BigInteger[].class);
					final GroupVector<GqElement, GqGroup> exponentiations = Arrays.stream(exponentiationsArray)
							.map(eA -> GqElementFactory.fromValue(eA, gqGroup))
							.collect(toGroupVector());

					// Parse decryption proof parameters
					final JsonData proof = input.getJsonData("proof");

					final ZqElement e = ZqElement.create(proof.get("e", BigInteger.class), zqGroup);
					final ZqElement z = ZqElement.create(proof.get("z", BigInteger.class), zqGroup);
					final ExponentiationProof exponentiationProof = new ExponentiationProof(e, z);

					// Parse auxiliary information parameters
					final String[] auxInformation = input.get("additional_information", String[].class);
					final List<String> auxiliaryInformation = Arrays.asList(auxInformation);

					// Parse output parameters
					final JsonData output = testParameters.getOutput();

					final Boolean result = output.get("verif_result", Boolean.class);

					return Arguments.of(bases, exponentiations, exponentiationProof, auxiliaryInformation, result, testParameters.getDescription());
				}
			});

		}

		@ParameterizedTest(name = "{5}")
		@MethodSource("jsonFileArgumentProvider")
		@DisplayName("with real values gives expected result")
		void verifyExponentiationProofWithRealValues(final GroupVector<GqElement, GqGroup> bases,
				final GroupVector<GqElement, GqGroup> exponentiations, final ExponentiationProof exponentiationProof,
				final List<String> auxiliaryInformation,
				final boolean expected, final String description) {
			final ExponentiationProofService exponentiationProofService = new ExponentiationProofService(randomService, HashService.getInstance());
			final boolean actual = assertDoesNotThrow(
					() -> exponentiationProofService.verifyExponentiation(bases, exponentiations, exponentiationProof, auxiliaryInformation));
			assertEquals(expected, actual, String.format("assertion failed for: %s", description));
		}
	}
}
