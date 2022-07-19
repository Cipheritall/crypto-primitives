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
package ch.post.it.evoting.cryptoprimitives.internal.mixnet;

import static ch.post.it.evoting.cryptoprimitives.internal.mixnet.SingleValueProductGenerator.genSingleValueProductWitness;
import static ch.post.it.evoting.cryptoprimitives.internal.mixnet.SingleValueProductGenerator.getSingleValueProductStatement;
import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.util.ArrayList;
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

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamal;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalService;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.mixnet.SingleValueProductArgument;
import ch.post.it.evoting.cryptoprimitives.mixnet.SingleValueProductStatement;
import ch.post.it.evoting.cryptoprimitives.mixnet.SingleValueProductWitness;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;
import ch.post.it.evoting.cryptoprimitives.utils.VerificationResult;

class SingleValueProductArgumentServiceTest extends TestGroupSetup {

	private static final ElGamal elGamal = new ElGamalService();
	private static final int NUM_ELEMENTS = 10;
	private static final RandomService randomService = new RandomService();

	private static HashService hashService;
	private static ElGamalMultiRecipientPublicKey publicKey;
	private static CommitmentKey commitmentKey;
	private static SingleValueProductArgumentService argumentService;

	private SingleValueProductStatement statement;
	private SingleValueProductWitness witness;

	@BeforeAll
	static void setupAll() {

		final ElGamalMultiRecipientKeyPair keyPair = elGamal.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		publicKey = keyPair.getPublicKey();
		final TestCommitmentKeyGenerator ckGenerator = new TestCommitmentKeyGenerator(gqGroup);
		commitmentKey = ckGenerator.genCommitmentKey(NUM_ELEMENTS);
		// Need to remove 0 as this can lead to a valid proof even though we expect invalid.
		hashService = TestHashService.create(BigInteger.ONE, gqGroup.getQ());
		argumentService = new SingleValueProductArgumentService(randomService, hashService, publicKey, commitmentKey);
	}

	@BeforeEach
	void setup() {
		witness = genSingleValueProductWitness(zqGroupGenerator, NUM_ELEMENTS);
		statement = getSingleValueProductStatement(witness, commitmentKey);
	}

	@Test
	@DisplayName("Constructing a SingleValueProductArgument with null arguments throws a NullPointerException")
	void constructSingleValueProductArgumentServiceWithNullArguments() {
		assertAll(
				() -> assertThrows(NullPointerException.class,
						() -> new SingleValueProductArgumentService(null, hashService, publicKey, commitmentKey)),
				() -> assertThrows(NullPointerException.class,
						() -> new SingleValueProductArgumentService(randomService, null, publicKey, commitmentKey)),
				() -> assertThrows(NullPointerException.class,
						() -> new SingleValueProductArgumentService(randomService, hashService, null, commitmentKey)),
				() -> assertThrows(NullPointerException.class,
						() -> new SingleValueProductArgumentService(randomService, hashService, publicKey, null))
		);
	}

	@Test
	@DisplayName("Constructing a SingleValueProductArgumentService with a hashService that has a too long hash length throws an IllegalArgumentException")
	void constructWithHashServiceWithTooLongHashLength() {
		final HashService otherHashService = HashService.getInstance();
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new SingleValueProductArgumentService(randomService, otherHashService, publicKey, commitmentKey));
		assertEquals("The hash service's bit length must be smaller than the bit length of q.", exception.getMessage());
	}

	@Nested
	@DisplayName("getSingleValueProductArgument...")
	class GetSingleValueProductArgumentTest {

		@RepeatedTest(10)
		void getSingleValueProductArgumentDoesNotThrow() {
			assertDoesNotThrow(() -> argumentService.getSingleValueProductArgument(statement, witness));
		}

		@Test
		@DisplayName("with null input throws NullPointerException")
		void getSingleValueProductArgumentWithNullThrows() {
			assertAll(
					() -> assertThrows(NullPointerException.class, () -> argumentService.getSingleValueProductArgument(null, witness)),
					() -> assertThrows(NullPointerException.class, () -> argumentService.getSingleValueProductArgument(statement, null))
			);
		}

		@Test
		@DisplayName("with statement groups different from commitment key group throws IllegalArgumentException")
		void getSingleValueProductArgumentWithStatementFromDifferentGroupsThrows() {
			final GqElement differentCommitment = otherGqGroup.getIdentity();
			final ZqElement differentProduct = otherZqGroup.getIdentity();
			final SingleValueProductStatement differentStatement = new SingleValueProductStatement(differentCommitment, differentProduct);
			final Exception exception = assertThrows(IllegalArgumentException.class,
					() -> argumentService.getSingleValueProductArgument(differentStatement, witness));
			assertEquals("The statement's groups must have the same order as the commitment key's group.", exception.getMessage());
		}

		@Test
		@DisplayName("with witness group order different from commitment key group order throws IllegalArgumentException")
		void getSingleValueProductArgumentWithWitnessFromDifferentGroupThrows() {
			final GroupVector<ZqElement, ZqGroup> differentElements = otherZqGroupGenerator.genRandomZqElementVector(NUM_ELEMENTS);
			final ZqElement differentRandomness = otherZqGroupGenerator.genRandomZqElementMember();
			final SingleValueProductWitness differentWitness = new SingleValueProductWitness(differentElements, differentRandomness);
			final Exception exception = assertThrows(IllegalArgumentException.class,
					() -> argumentService.getSingleValueProductArgument(statement, differentWitness));
			assertEquals("The witness' group must have the same order as the commitment key's group.", exception.getMessage());
		}

		@Test
		@DisplayName("with witness of size n < 2 throws IllegalArgumentException")
		void getSingleValueProductArgumentWithNSmallerTwo() {
			witness = genSingleValueProductWitness(zqGroupGenerator, 1);
			statement = getSingleValueProductStatement(witness, commitmentKey);

			final Exception exception = assertThrows(IllegalArgumentException.class,
					() -> argumentService.getSingleValueProductArgument(statement, witness));
			assertEquals("The size n of the witness must be at least 2.", exception.getMessage());
		}

		@Test
		@DisplayName("with incorrect commitment throws IllegalArgumentException")
		void getSingleValueProductArgumentWithWrongCommitmentThrows() {
			final GqElement commitment = statement.get_c_a();
			final GqElement wrongCommitment = commitment.multiply(commitment.getGroup().getGenerator());
			final SingleValueProductStatement wrongStatement = new SingleValueProductStatement(wrongCommitment, statement.get_b());
			final Exception exception = assertThrows(IllegalArgumentException.class,
					() -> argumentService.getSingleValueProductArgument(wrongStatement, witness));
			assertEquals("The provided commitment does not correspond to the elements, randomness and commitment key provided.",
					exception.getMessage());
		}

		@Test
		@DisplayName("with incorrect product throws IllegalArgumentException")
		void getSingleValueProductArgumentWithWrongProductThrows() {
			final ZqElement product = statement.get_b();
			final ZqElement wrongProduct = product.add(ZqElement.create(BigInteger.ONE, product.getGroup()));
			final SingleValueProductStatement wrongStatement = new SingleValueProductStatement(statement.get_c_a(), wrongProduct);
			final Exception exception = assertThrows(IllegalArgumentException.class,
					() -> argumentService.getSingleValueProductArgument(wrongStatement, witness));
			assertEquals("The product of the provided elements does not give the provided product.", exception.getMessage());
		}

		@Test
		@DisplayName("with specific values gives expected result")
		void getSingleValueProductArgumentWithSpecificValues() {

			final GqGroup specificGqGroup = new GqGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(6));
			final ZqGroup specificZqGroup = ZqGroup.sameOrderAs(specificGqGroup);
			// commitment = 3
			final GqElement commitment = GqElementFactory.fromValue(BigInteger.valueOf(3), specificGqGroup);
			// product = 9
			final ZqElement product = ZqElement.create(BigInteger.valueOf(9), specificZqGroup);
			// a = (2, 10)
			final List<ZqElement> a = new ArrayList<>();
			a.add(ZqElement.create(BigInteger.valueOf(2), specificZqGroup));
			a.add(ZqElement.create(BigInteger.TEN, specificZqGroup));
			// r = 5
			final ZqElement r = ZqElement.create(BigInteger.valueOf(5), specificZqGroup);
			// pk = (8, 16)
			final List<GqElement> pkElements = new ArrayList<>(2);
			pkElements.add(GqElementFactory.fromValue(BigInteger.valueOf(8), specificGqGroup));
			pkElements.add(GqElementFactory.fromValue(BigInteger.valueOf(16), specificGqGroup));
			final ElGamalMultiRecipientPublicKey pk = new ElGamalMultiRecipientPublicKey(pkElements);
			// ck = (2, 3, 4)
			final List<GqElement> gElements = new ArrayList<>(2);
			final GqElement h = GqElementFactory.fromValue(BigInteger.valueOf(2), specificGqGroup);
			gElements.add(GqElementFactory.fromValue(BigInteger.valueOf(3), specificGqGroup));
			gElements.add(GqElementFactory.fromValue(BigInteger.valueOf(4), specificGqGroup));
			final CommitmentKey ck = new CommitmentKey(h, gElements);
			// expected = (16, 2, 3, (1, 8), (1, 2), 5, 7)
			final GqElement cd = GqElementFactory.fromValue(BigInteger.valueOf(16), specificGqGroup);
			final GqElement cdelta = GqElementFactory.fromValue(BigInteger.valueOf(2), specificGqGroup);
			final GqElement cDelta = GqElementFactory.fromValue(BigInteger.valueOf(3), specificGqGroup);
			final List<ZqElement> aTilde = new ArrayList<>(2);
			aTilde.add(ZqElement.create(BigInteger.ONE, specificZqGroup));
			aTilde.add(ZqElement.create(BigInteger.valueOf(8), specificZqGroup));
			final List<ZqElement> bTilde = new ArrayList<>(2);
			bTilde.add(ZqElement.create(BigInteger.ONE, specificZqGroup));
			bTilde.add(ZqElement.create(BigInteger.valueOf(2), specificZqGroup));
			final ZqElement rTilde = ZqElement.create(BigInteger.valueOf(5), specificZqGroup);
			final ZqElement sTilde = ZqElement.create(BigInteger.valueOf(7), specificZqGroup);
			final SingleValueProductArgument expected = new SingleValueProductArgument.Builder()
					.with_c_d(cd)
					.with_c_delta(cdelta)
					.with_c_Delta(cDelta)
					.with_a_tilde(GroupVector.from(aTilde))
					.with_b_tilde(GroupVector.from(bTilde))
					.with_r_tilde(rTilde)
					.with_s_tilde(sTilde)
					.build();

			//Mock random integers
			final RandomService randomService = spy(new RandomService());
			doReturn(BigInteger.valueOf(3), BigInteger.valueOf(7), // d_0, d_1
					BigInteger.TEN,                        // r_d
					BigInteger.valueOf(4), BigInteger.valueOf(8))  // s_0, s_x
					.when(randomService).genRandomInteger(specificZqGroup.getQ());

			final SingleValueProductStatement statement = new SingleValueProductStatement(commitment, product);
			final SingleValueProductWitness witness = new SingleValueProductWitness(GroupVector.from(a), r);

			final HashService hashService = mock(HashService.class);
			when(hashService.recursiveHash(any()))
					.thenReturn(new byte[] { 0b1010 });
			final SingleValueProductArgumentService svpArgumentProvider = new SingleValueProductArgumentService(randomService, hashService, pk, ck);
			assertEquals(expected, svpArgumentProvider.getSingleValueProductArgument(statement, witness));
		}
	}

	@Nested
	@DisplayName("verifySingleValueProductArgument...")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VerifySingleValueProductArgumentServiceTest {

		private SingleValueProductArgument argument;

		@BeforeEach
		void setup() {
			argument = argumentService.getSingleValueProductArgument(statement, witness);
		}

		@Test
		@DisplayName("with null arguments throws a NullPointerException")
		void verifySingleValueProductArgumentWithNullArguments() {
			assertThrows(NullPointerException.class, () -> argumentService.verifySingleValueProductArgument(null, argument));
			assertThrows(NullPointerException.class, () -> argumentService.verifySingleValueProductArgument(statement, null));
		}

		@Test
		@DisplayName("with statement and argument having different groups throws an IllegalArgumentException")
		void verifySingleValueProductArgumentWithIncompatibleStatementAndArgument() {
			final GqElement commitment = otherGqGroupGenerator.genMember();
			final ZqElement product = otherZqGroupGenerator.genRandomZqElementMember();
			statement = new SingleValueProductStatement(commitment, product);
			final Exception exception = assertThrows(IllegalArgumentException.class,
					() -> argumentService.verifySingleValueProductArgument(statement, argument));
			assertEquals("The statement and the argument must have compatible groups.", exception.getMessage());
		}

		@Test
		@DisplayName("with a correct argument returns true")
		void verifySingleValueProductArgumentWithCorrectArgument() {
			final VerificationResult verificationResult = argumentService.verifySingleValueProductArgument(statement, argument).verify();
			assertTrue(verificationResult.isVerified());
		}

		@Test
		@DisplayName("with an incorrect statement returns false")
		void verifySingleValueProductArgumentWithIncorrectStatement() {
			GqElement commitment = statement.get_c_a();
			commitment = commitment.multiply(gqGroup.getGenerator());
			final ZqElement product = statement.get_b();
			statement = new SingleValueProductStatement(commitment, product);

			final VerificationResult verificationResult = argumentService.verifySingleValueProductArgument(statement, argument).verify();
			assertFalse(verificationResult.isVerified());
		}

		@ParameterizedTest
		@MethodSource("verifySingleValueProductArgumentRealValuesProvider")
		@DisplayName("with real values gives expected result")
		void verifySingleValueProductArgumentRealValues(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey,
				final SingleValueProductStatement singleValueProductStatement, final SingleValueProductArgument singleValueProductArgument,
				final boolean expectedOutput, final String description) {

			final HashService hashService = HashService.getInstance();

			final SingleValueProductArgumentService service = new SingleValueProductArgumentService(randomService, hashService, publicKey,
					commitmentKey);

			assertEquals(expectedOutput,
					service.verifySingleValueProductArgument(singleValueProductStatement, singleValueProductArgument).verify().isVerified(),
					String.format("assertion failed for: %s", description));
		}

		Stream<Arguments> verifySingleValueProductArgumentRealValuesProvider() {
			final List<TestParameters> parametersList = TestParameters.fromResource("/mixnet/verify-single-value-product-argument.json");

			return parametersList.stream().parallel().map(testParameters -> {
				// Context.
				final JsonData contextData = testParameters.getContext();
				final TestContextParser context = new TestContextParser(contextData);

				final GqGroup gqGroup = context.getGqGroup();
				final ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);

				final ElGamalMultiRecipientPublicKey publicKey = context.parsePublicKey();
				final CommitmentKey commitmentKey = context.parseCommitmentKey();

				// Inputs.
				final JsonData input = testParameters.getInput();
				final SingleValueProductStatement singleValueProductStatement = parseSingleValueProductStatement(gqGroup, zqGroup, input);
				final JsonData singleValueProductArgumentData = input.getJsonData("argument");
				final TestArgumentParser argumentParser = new TestArgumentParser(gqGroup);
				final SingleValueProductArgument singleValueProductArgument = argumentParser
						.parseSingleValueProductArgument(singleValueProductArgumentData);

				// Output.
				final JsonData output = testParameters.getOutput();
				final boolean outputValue = Boolean.parseBoolean(output.getJsonData("result").toString());

				return Arguments.of(publicKey, commitmentKey, singleValueProductStatement, singleValueProductArgument, outputValue,
						testParameters.getDescription());
			});
		}

		private SingleValueProductStatement parseSingleValueProductStatement(final GqGroup gqGroup, final ZqGroup zqGroup, final JsonData input) {
			final JsonData svpStatement = input.getJsonData("statement");
			final BigInteger caValue = svpStatement.get("c_a", BigInteger.class);
			final BigInteger bValue = svpStatement.get("b", BigInteger.class);

			final GqElement ca = GqElementFactory.fromValue(caValue, gqGroup);
			final ZqElement b = ZqElement.create(bValue, zqGroup);

			return new SingleValueProductStatement(ca, b);
		}
	}

}
