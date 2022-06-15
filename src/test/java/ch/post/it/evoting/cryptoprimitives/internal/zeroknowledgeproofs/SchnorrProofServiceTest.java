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
package ch.post.it.evoting.cryptoprimitives.internal.zeroknowledgeproofs;

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static ch.post.it.evoting.cryptoprimitives.internal.zeroknowledgeproofs.SchnorrProofService.computePhiSchnorr;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

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
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;

import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;
import ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.SchnorrProof;

@DisplayName("SchnorrProofService calling")
class SchnorrProofServiceTest extends TestGroupSetup {

	private static ElGamalGenerator elGamalGenerator;
	private static RandomService randomService;
	private static SchnorrProofService schnorrProofService;

	@BeforeAll
	static void setUpAll() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		randomService = new RandomService();

		final HashService hashService = TestHashService.create(gqGroup.getQ());
		schnorrProofService = new SchnorrProofService(randomService, hashService);
	}

	@Nested
	@DisplayName("computePhiSchnorr with")
	class computePhiSchnorr {

		private ZqElement exponent;
		private GqElement base;

		@BeforeEach
		void setUp() {
			base = gqGroupGenerator.genMember();
			exponent = zqGroupGenerator.genRandomZqElementMember();
		}

		@Test
		@DisplayName("valid parameters does not throw")
		void validParams() {
			final GqElement result = computePhiSchnorr(exponent, base);
			assertEquals(1, result.size());
		}

		@Test
		@DisplayName("null parameters throws NullPointerException")
		void nullParams() {
			assertThrows(NullPointerException.class, () -> computePhiSchnorr(null, base));
			assertThrows(NullPointerException.class, () -> computePhiSchnorr(exponent, null));
		}

		@Test
		@DisplayName("specific values gives expected image")
		void specificValues() {
			final GqGroup gqGroup = new GqGroup(BigInteger.valueOf(11), BigInteger.valueOf(5), BigInteger.valueOf(3));
			final ZqGroup zqGroup = new ZqGroup(BigInteger.valueOf(5));

			final ZqElement zeroZq = ZqElement.create(BigInteger.valueOf(0), zqGroup);
			final ZqElement threeGq = ZqElement.create(BigInteger.valueOf(3), zqGroup);

			final GqElement one = GqElementFactory.fromValue(BigInteger.valueOf(1), gqGroup);
			final GqElement three = GqElementFactory.fromValue(BigInteger.valueOf(3), gqGroup);
			final GqElement four = GqElementFactory.fromValue(BigInteger.valueOf(4), gqGroup);
			final GqElement five = GqElementFactory.fromValue(BigInteger.valueOf(5), gqGroup);
			final GqElement nine = GqElementFactory.fromValue(BigInteger.valueOf(9), gqGroup);

			final GqElement resultZeroOne = computePhiSchnorr(zeroZq, one);
			final GqElement resultZeroFour = computePhiSchnorr(zeroZq, four);
			final GqElement resultZeroFive = computePhiSchnorr(zeroZq, five);
			final GqElement resultZeroNine = computePhiSchnorr(zeroZq, nine);

			final GqElement resultThreeOne = computePhiSchnorr(threeGq, one);
			final GqElement resultThreeFour = computePhiSchnorr(threeGq, four);
			final GqElement resultThreeFive = computePhiSchnorr(threeGq, five);
			final GqElement resultThreeNine = computePhiSchnorr(threeGq, nine);

			final GqElement expectedOneImage = one;
			final GqElement expectedThreeImage = three;
			final GqElement expectedFourImage = four;
			final GqElement expectedNineImage = nine;

			assertEquals(expectedOneImage, resultZeroOne);
			assertEquals(expectedOneImage, resultZeroFour);
			assertEquals(expectedOneImage, resultZeroFive);
			assertEquals(expectedOneImage, resultZeroNine);

			assertEquals(expectedOneImage, resultThreeOne);
			assertEquals(expectedNineImage, resultThreeFour);
			assertEquals(expectedFourImage, resultThreeFive);
			assertEquals(expectedThreeImage, resultThreeNine);
		}
	}

	@Nested
	@DisplayName("genSchnorrProof with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class GenSchnorrProof {

		private static final int STR_LEN = 2;
		private GqElement statement;
		private ZqElement witness;
		private List<String> auxiliaryInformation;

		@BeforeEach
		void setUp() {
			witness = zqGroupGenerator.genRandomZqElementMember();
			statement = gqGroupGenerator.genMember().getGroup().getGenerator().exponentiate(witness);
			auxiliaryInformation = Arrays.asList(randomService.genRandomBase16String(STR_LEN), randomService.genRandomBase64String(STR_LEN));
		}

		@Test
		@DisplayName("valid parameters does not throw")
		void validParams() {
			assertDoesNotThrow(
					() -> schnorrProofService.genSchnorrProof(witness, statement, auxiliaryInformation));
		}

		@Test
		@DisplayName("null parameters throws NullPointerException")
		void nullParams() {
			assertThrows(NullPointerException.class, () -> schnorrProofService
					.genSchnorrProof(null, statement, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> schnorrProofService
					.genSchnorrProof(witness, null, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> schnorrProofService
					.genSchnorrProof(witness, statement, null));
		}

		@Test
		@DisplayName("auxiliary information containing null throws IllegalArgumentException")
		void auxiliaryInformationWithNull() {
			auxiliaryInformation.set(0, null);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> schnorrProofService
					.genSchnorrProof(witness, statement, auxiliaryInformation));
			assertEquals("The auxiliary information must not contain null objects.", exception.getMessage());
		}

		@Test
		@DisplayName("specific values gives expected proof")
		void specificValues() {

			// Inputs.
			final BigInteger p = BigInteger.valueOf(47);
			final BigInteger q = BigInteger.valueOf(23);
			final BigInteger g = BigInteger.valueOf(2);

			final GqGroup gqGroup = new GqGroup(p, q, g);
			final ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);

			auxiliaryInformation = Arrays.asList("aux", "info");
			statement = GqElementFactory.fromValue(BigInteger.valueOf(32), gqGroup);
			witness = ZqElement.create(5, zqGroup);

			// Service creation.
			final RandomService mockRandomService = mock(RandomService.class);
			when(mockRandomService.genRandomInteger(q)).thenReturn(BigInteger.valueOf(2));

			final HashService hashService = TestHashService.create(gqGroup.getQ());
			final SchnorrProofService SchnorrProofService = new SchnorrProofService(mockRandomService, hashService);

			// Expected proof.
			final ZqElement e = ZqElement.create(11, zqGroup);
			final ZqElement z = ZqElement.create(11, zqGroup);

			final SchnorrProof expectedProof = new SchnorrProof(e, z);

			assertEquals(expectedProof, SchnorrProofService
					.genSchnorrProof(witness, statement, auxiliaryInformation));
		}
	}

	@Nested
	@DisplayName("verifySchnorrProof with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VerifySchnorrProof {

		private static final int STR_LEN = 4;
		private GqElement statement;
		private List<String> auxiliaryInformation;
		private ZqElement witness;
		private SchnorrProof schnorrProof;

		@BeforeEach
		void setUp() {
			statement = gqGroupGenerator.genMember();
			witness = zqGroupGenerator.genRandomZqElementMember();
			statement = statement.getGroup().getGenerator().exponentiate(witness);
			auxiliaryInformation = Arrays.asList(randomService.genRandomBase16String(STR_LEN), randomService.genRandomBase64String(STR_LEN));
			schnorrProof = schnorrProofService.genSchnorrProof(witness, statement, auxiliaryInformation);
		}

		@Test
		@DisplayName("valid parameters returns true")
		void validParams() {
			assertTrue(schnorrProofService.verifySchnorrProof(schnorrProof, statement, auxiliaryInformation));
		}

		@Test
		@DisplayName("empty auxiliary information returns true")
		void emptyAux() {
			final SchnorrProof schnorrProof = schnorrProofService.genSchnorrProof(witness, statement, Collections.emptyList());
			assertTrue(schnorrProofService.verifySchnorrProof(schnorrProof, statement, Collections.emptyList()));
		}

		@Test
		@DisplayName("null parameters throws NullPointerException")
		void nullParams() {
			assertThrows(NullPointerException.class, () -> schnorrProofService
					.verifySchnorrProof(null, statement, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> schnorrProofService
					.verifySchnorrProof(schnorrProof, null, auxiliaryInformation));
			assertThrows(NullPointerException.class, () -> schnorrProofService
					.verifySchnorrProof(schnorrProof, statement, null));
		}

		@Test
		@DisplayName("auxiliary information containing null throws IllegalArgumentException")
		void auxiliaryInformationWithNull() {
			auxiliaryInformation.set(0, null);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> schnorrProofService
					.verifySchnorrProof(schnorrProof, statement, auxiliaryInformation));
			assertEquals("The auxiliary information must not contain null objects.", exception.getMessage());
		}

		private Stream<Arguments> jsonFileArgumentProvider() {
			final List<TestParameters> parametersList = TestParameters.fromResource("/zeroknowledgeproofs/verify-schnorr.json");

			return parametersList.stream().parallel().map(testParameters -> {
				// Context.
				final JsonData context = testParameters.getContext();
				final BigInteger p = context.get("p", BigInteger.class);
				final BigInteger q = context.get("q", BigInteger.class);
				final BigInteger g = context.get("g", BigInteger.class);

				try (final MockedStatic<SecurityLevelConfig> mockedSecurityLevel = mockStatic(SecurityLevelConfig.class)) {
					mockedSecurityLevel.when(SecurityLevelConfig::getSystemSecurityLevel).thenReturn(testParameters.getSecurityLevel());
					final GqGroup gqGroup = new GqGroup(p, q, g);
					final ZqGroup zqGroup = new ZqGroup(q);

					final JsonData input = testParameters.getInput();

					// Parse statement (statement) parameter
					final BigInteger state = input.get("statement", BigInteger.class);
					final GqElement statement = GqElementFactory.fromValue(state, gqGroup);

					// Parse SchnorrProof (proof) parameters
					final JsonData proof = input.getJsonData("proof");

					final ZqElement e = ZqElement.create(proof.get("e", BigInteger.class), zqGroup);
					final ZqElement z = ZqElement.create(proof.get("z", BigInteger.class), zqGroup);
					final SchnorrProof schnorrProof = new SchnorrProof(e, z);

					// Parse auxiliaryInformation parameters (i_aux)
					final String[] auxInformation = input.get("additional_information", String[].class);
					final List<String> auxiliaryInformation = Arrays.asList(auxInformation);

					// Parse output parameters
					final JsonData output = testParameters.getOutput();

					final Boolean result = output.get("result", Boolean.class);

					return Arguments
							.of(schnorrProof, statement, auxiliaryInformation,
									result, testParameters.getDescription());
				}
			});
		}

		@ParameterizedTest()
		@MethodSource("jsonFileArgumentProvider")
		@DisplayName("with real values gives expected result")
		void verifySchnorrProofWithRealValues(final SchnorrProof schnorrProof, final GqElement statement, final List<String> auxiliaryInformation,
				final boolean expected, final String description) {

			final SchnorrProofService SchnorrProofService = new SchnorrProofService(randomService,
					HashService.getInstance());
			final boolean actual = SchnorrProofService.verifySchnorrProof(schnorrProof, statement, auxiliaryInformation);
			assertEquals(expected, actual, String.format("assertion failed for: %s", description));
		}
	}
}
