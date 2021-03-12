/*
 * Copyright 2021 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;
import static java.util.stream.Collectors.toList;
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
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

import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

class SingleValueProductArgumentServiceTest {

	private static final int NUM_ELEMENTS = 10;
	private static final RandomService randomService = new RandomService();

	private static GqGroup gqGroup;
	private static ZqGroup zqGroup;
	private static ZqGroupGenerator zqGroupGenerator;
	private static MixnetHashService hashService;
	private static ElGamalMultiRecipientPublicKey publicKey;
	private static CommitmentKey commitmentKey;
	private static SingleValueProductArgumentService argumentService;

	private GqElement commitment;
	private ZqElement product;

	private SingleValueProductStatement statement;
	private SingleValueProductWitness witness;

	@BeforeAll
	static void setupAll() {
		gqGroup = GroupTestData.getGqGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		zqGroupGenerator = new ZqGroupGenerator(zqGroup);

		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, NUM_ELEMENTS, randomService);
		publicKey = keyPair.getPublicKey();
		CommitmentKeyGenerator ckGenerator = new CommitmentKeyGenerator(gqGroup);
		commitmentKey = ckGenerator.genCommitmentKey(NUM_ELEMENTS);
		hashService = TestHashService.create(BigInteger.ZERO, gqGroup.getQ());
		argumentService = new SingleValueProductArgumentService(randomService, hashService, publicKey, commitmentKey);
	}

	@BeforeEach
	void setup() {
		SameGroupVector<ZqElement, ZqGroup> elements = zqGroupGenerator.genRandomZqElementVector(NUM_ELEMENTS);
		ZqElement randomness = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		product = elements.stream().reduce(ZqElement.create(BigInteger.ONE, zqGroup), ZqElement::multiply);
		commitment = CommitmentService.getCommitment(elements, randomness, commitmentKey);

		statement = new SingleValueProductStatement(commitment, product);
		witness = new SingleValueProductWitness(elements, randomness);
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
			GqGroup differentGqGroup = GroupTestData.getDifferentGqGroup(commitmentKey.getGroup());
			ZqGroup differentZqGroup = ZqGroup.sameOrderAs(differentGqGroup);
			GqElement differentCommitment = differentGqGroup.getIdentity();
			ZqElement differentProduct = differentZqGroup.getIdentity();
			SingleValueProductStatement differentStatement = new SingleValueProductStatement(differentCommitment, differentProduct);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> argumentService.getSingleValueProductArgument(differentStatement, witness));
			assertEquals("The statement's groups must have the same order as the commitment key's group.", exception.getMessage());
		}

		@Test
		@DisplayName("with witness group order different from commitment key group order throws IllegalArgumentException")
		void getSingleValueProductArgumentWithWitnessFromDifferentGroupThrows() {
			GqGroup differentGqGroup = GroupTestData.getDifferentGqGroup(commitmentKey.getGroup());
			ZqGroup differentZqGroup = ZqGroup.sameOrderAs(differentGqGroup);
			ZqGroupGenerator differentZqGroupGenerator = new ZqGroupGenerator(differentZqGroup);
			SameGroupVector<ZqElement, ZqGroup> differentElements = differentZqGroupGenerator.genRandomZqElementVector(NUM_ELEMENTS);
			ZqElement differentRandomness = ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup);
			SingleValueProductWitness differentWitness = new SingleValueProductWitness(differentElements, differentRandomness);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> argumentService.getSingleValueProductArgument(statement, differentWitness));
			assertEquals("The witness' group must have the same order as the commitment key's group.", exception.getMessage());
		}

		@Test
		@DisplayName("with witness of size n < 2 throws IllegalArgumentException")
		void getSingleValueProductArgumentWithNSmallerTwo() {
			SameGroupVector<ZqElement, ZqGroup> elements = zqGroupGenerator.genRandomZqElementVector(1);
			ZqElement randomness = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
			product = elements.stream().reduce(ZqElement.create(BigInteger.ONE, zqGroup), ZqElement::multiply);
			commitment = CommitmentService.getCommitment(elements, randomness, commitmentKey);

			statement = new SingleValueProductStatement(commitment, product);
			witness = new SingleValueProductWitness(elements, randomness);

			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> argumentService.getSingleValueProductArgument(statement, witness));
			assertEquals("The size n of the witness must be at least 2.", exception.getMessage());
		}

		@Test
		@DisplayName("with incorrect commitment throws IllegalArgumentException")
		void getSingleValueProductArgumentWithWrongCommitmentThrows() {
			GqElement wrongCommitment = commitment.multiply(commitment.getGroup().getGenerator());
			SingleValueProductStatement wrongStatement = new SingleValueProductStatement(wrongCommitment, product);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> argumentService.getSingleValueProductArgument(wrongStatement, witness));
			assertEquals("The provided commitment does not correspond to the elements, randomness and commitment key provided.",
					exception.getMessage());
		}

		@Test
		@DisplayName("with incorrect product throws IllegalArgumentException")
		void getSingleValueProductArgumentWithWrongProductThrows() {
			ZqElement wrongProduct = product.add(ZqElement.create(BigInteger.ONE, product.getGroup()));
			SingleValueProductStatement wrongStatement = new SingleValueProductStatement(commitment, wrongProduct);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> argumentService.getSingleValueProductArgument(wrongStatement, witness));
			assertEquals("The product of the provided elements does not give the provided product.", exception.getMessage());
		}

		@Test
		@DisplayName("with specific values gives expected result")
		void getSingleValueProductArgumentWithSpecificValues() {
			GqGroup specificGqGroup = new GqGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(6));
			ZqGroup specificZqGroup = ZqGroup.sameOrderAs(specificGqGroup);
			// commitment = 3
			GqElement commitment = GqElement.create(BigInteger.valueOf(3), specificGqGroup);
			// product = 9
			ZqElement product = ZqElement.create(BigInteger.valueOf(9), specificZqGroup);
			// a = (2, 10)
			List<ZqElement> a = new ArrayList<>();
			a.add(ZqElement.create(BigInteger.valueOf(2), specificZqGroup));
			a.add(ZqElement.create(BigInteger.valueOf(10), specificZqGroup));
			// r = 5
			ZqElement r = ZqElement.create(BigInteger.valueOf(5), specificZqGroup);
			// pk = (8, 16)
			List<GqElement> pkElements = new ArrayList<>(2);
			pkElements.add(GqElement.create(BigInteger.valueOf(8), specificGqGroup));
			pkElements.add(GqElement.create(BigInteger.valueOf(16), specificGqGroup));
			ElGamalMultiRecipientPublicKey pk = new ElGamalMultiRecipientPublicKey(pkElements);
			// ck = (2, 3, 4)
			List<GqElement> gElements = new ArrayList<>(2);
			GqElement h = GqElement.create(BigInteger.valueOf(2), specificGqGroup);
			gElements.add(GqElement.create(BigInteger.valueOf(3), specificGqGroup));
			gElements.add(GqElement.create(BigInteger.valueOf(4), specificGqGroup));
			CommitmentKey ck = new CommitmentKey(h, gElements);
			// expected = (16, 2, 3, (1, 8), (1, 2), 5, 7)
			GqElement cd = GqElement.create(BigInteger.valueOf(16), specificGqGroup);
			GqElement cdelta = GqElement.create(BigInteger.valueOf(2), specificGqGroup);
			GqElement cDelta = GqElement.create(BigInteger.valueOf(3), specificGqGroup);
			List<ZqElement> aTilde = new ArrayList<>(2);
			aTilde.add(ZqElement.create(BigInteger.valueOf(1), specificZqGroup));
			aTilde.add(ZqElement.create(BigInteger.valueOf(8), specificZqGroup));
			List<ZqElement> bTilde = new ArrayList<>(2);
			bTilde.add(ZqElement.create(BigInteger.valueOf(1), specificZqGroup));
			bTilde.add(ZqElement.create(BigInteger.valueOf(2), specificZqGroup));
			ZqElement rTilde = ZqElement.create(BigInteger.valueOf(5), specificZqGroup);
			ZqElement sTilde = ZqElement.create(BigInteger.valueOf(7), specificZqGroup);
			SingleValueProductArgument expected = new SingleValueProductArgument.Builder()
					.withCd(cd)
					.withCLowerDelta(cdelta)
					.withCUpperDelta(cDelta)
					.withATilde(SameGroupVector.from(aTilde))
					.withBTilde(SameGroupVector.from(bTilde))
					.withRTilde(rTilde)
					.withSTilde(sTilde)
					.build();

			//Mock random integers
			RandomService randomService = spy(new RandomService());
			doReturn(BigInteger.valueOf(3), BigInteger.valueOf(7), // d_0, d_1
					BigInteger.valueOf(10),                        // r_d
					BigInteger.valueOf(4), BigInteger.valueOf(8))  // s_0, s_x
					.when(randomService).genRandomInteger(specificZqGroup.getQ());

			SingleValueProductStatement statement = new SingleValueProductStatement(commitment, product);
			SingleValueProductWitness witness = new SingleValueProductWitness(SameGroupVector.from(a), r);

			MixnetHashService hashService = mock(MixnetHashService.class);
			when(hashService.recursiveHash(any()))
					.thenReturn(new byte[] { 0b1010 });
			SingleValueProductArgumentService svpArgumentProvider = new SingleValueProductArgumentService(randomService, hashService, pk, ck);
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
			GqGroup differentGqGroup = GroupTestData.getDifferentGqGroup(gqGroup);
			ZqGroup differentZqGroup = ZqGroup.sameOrderAs(differentGqGroup);
			GqGroupGenerator differentGqGroupGenerator = new GqGroupGenerator(differentGqGroup);
			ZqGroupGenerator differentZqGroupGenerator = new ZqGroupGenerator(differentZqGroup);
			GqElement commitment = differentGqGroupGenerator.genMember();
			ZqElement product = differentZqGroupGenerator.genRandomZqElementMember();
			statement = new SingleValueProductStatement(commitment, product);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> argumentService.verifySingleValueProductArgument(statement, argument));
			assertEquals("The statement and the argument must have compatible groups.", exception.getMessage());
		}

		@Test
		@DisplayName("with a correct argument returns true")
		void verifySingleValueProductArgumentWithCorrectArgument() {
			assertTrue(argumentService.verifySingleValueProductArgument(statement, argument));
		}

		@Test
		@DisplayName("with an incorrect argument returns false")
		void verifySingleValueProductArgumentWithIncorrectArgument() {
			GqElement commitment = statement.getCommitment();
			commitment = commitment.multiply(gqGroup.getGenerator());
			ZqElement product = statement.getProduct();
			statement = new SingleValueProductStatement(commitment, product);
			assertFalse(argumentService.verifySingleValueProductArgument(statement, argument));
		}

		@ParameterizedTest
		@MethodSource("verifySingleValueProductArgumentRealValuesProvider")
		@DisplayName("with real values gives expected result")
		void verifySingleValueProductArgumentRealValues(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey,
				final SingleValueProductStatement singleValueProductStatement, final SingleValueProductArgument singleValueProductArgument,
				final boolean expectedOutput, String description) throws NoSuchAlgorithmException {

			final HashService hashService = new HashService(MessageDigest.getInstance("SHA-256"));
			final MixnetHashService mixnetHashService = new MixnetHashService(hashService, publicKey.getGroup().getQ().bitLength());

			final SingleValueProductArgumentService service = new SingleValueProductArgumentService(randomService, mixnetHashService, publicKey,
					commitmentKey);

			assertEquals(expectedOutput, service.verifySingleValueProductArgument(singleValueProductStatement, singleValueProductArgument),
					String.format("assertion failed for: %s", description));
		}

		Stream<Arguments> verifySingleValueProductArgumentRealValuesProvider() {
			final List<TestParameters> parametersList = TestParameters.fromResource("/mixnet/verify-single-value-product-argument.json");

			return parametersList.stream().parallel().map(testParameters -> {
				// Context.
				final JsonData context = testParameters.getContext();

				final BigInteger p = context.get("p", BigInteger.class);
				final BigInteger q = context.get("q", BigInteger.class);
				final BigInteger g = context.get("g", BigInteger.class);

				final GqGroup gqGroup = new GqGroup(p, q, g);
				final ZqGroup zqGroup = new ZqGroup(q);

				final BigInteger[] pkValues = context.get("pk", BigInteger[].class);
				final List<GqElement> keyElements = Arrays.stream(pkValues)
						.map(bi -> GqElement.create(bi, gqGroup))
						.collect(toList());
				final ElGamalMultiRecipientPublicKey publicKey = new ElGamalMultiRecipientPublicKey(keyElements);

				final BigInteger hValue = context.getJsonData("ck").get("h", BigInteger.class);
				final BigInteger[] gValues = context.getJsonData("ck").get("g", BigInteger[].class);
				final GqElement h = GqElement.create(hValue, gqGroup);
				final List<GqElement> gElements = Arrays.stream(gValues)
						.map(bi -> GqElement.create(bi, gqGroup))
						.collect(toList());
				final CommitmentKey commitmentKey = new CommitmentKey(h, gElements);

				// Inputs.
				final JsonData input = testParameters.getInput();
				final SingleValueProductStatement singleValueProductStatement = parseSingleValueProductStatement(gqGroup, zqGroup, input);
				final SingleValueProductArgument singleValueProductArgument = parseSingleValueProductArgument(gqGroup, zqGroup, input);

				// Output.
				final JsonData output = testParameters.getOutput();
				final boolean outputValue = output.get("verif_result", Boolean.class);

				return Arguments.of(publicKey, commitmentKey, singleValueProductStatement, singleValueProductArgument, outputValue,
						testParameters.getDescription());
			});
		}

		private SingleValueProductStatement parseSingleValueProductStatement(final GqGroup gqGroup, final ZqGroup zqGroup, final JsonData input) {
			final JsonData svpStatement = input.getJsonData("statement");
			final BigInteger caValue = svpStatement.get("c_a", BigInteger.class);
			final BigInteger bValue = svpStatement.get("b", BigInteger.class);

			final GqElement ca = GqElement.create(caValue, gqGroup);
			final ZqElement b = ZqElement.create(bValue, zqGroup);

			return new SingleValueProductStatement(ca, b);
		}

		private SingleValueProductArgument parseSingleValueProductArgument(final GqGroup gqGroup, final ZqGroup zqGroup, final JsonData input) {
			final JsonData svpArgument = input.getJsonData("argument");
			final BigInteger cdValue = svpArgument.get("c_d", BigInteger.class);
			final BigInteger cLowerDeltaValue = svpArgument.get("c_lower_delta", BigInteger.class);
			final BigInteger cUpperDeltaValue = svpArgument.get("c_upper_delta", BigInteger.class);
			final BigInteger[] aTildeValues = svpArgument.get("a_tilde", BigInteger[].class);
			final BigInteger[] bTildeValues = svpArgument.get("b_tilde", BigInteger[].class);
			final BigInteger rTildeValue = svpArgument.get("r_tilde", BigInteger.class);
			final BigInteger sTildeValue = svpArgument.get("s_tilde", BigInteger.class);

			final GqElement cd = GqElement.create(cdValue, gqGroup);
			final GqElement cLowerDelta = GqElement.create(cLowerDeltaValue, gqGroup);
			final GqElement cUpperDelta = GqElement.create(cUpperDeltaValue, gqGroup);
			final SameGroupVector<ZqElement, ZqGroup> aTilde = Arrays.stream(aTildeValues)
					.map(bi -> ZqElement.create(bi, zqGroup))
					.collect(toSameGroupVector());
			final SameGroupVector<ZqElement, ZqGroup> bTilde = Arrays.stream(bTildeValues)
					.map(bi -> ZqElement.create(bi, zqGroup))
					.collect(toSameGroupVector());
			final ZqElement rTilde = ZqElement.create(rTildeValue, zqGroup);
			final ZqElement sTilde = ZqElement.create(sTildeValue, zqGroup);

			return new SingleValueProductArgument.Builder()
					.withCd(cd)
					.withCLowerDelta(cLowerDelta)
					.withCUpperDelta(cUpperDelta)
					.withATilde(aTilde)
					.withBTilde(bTilde)
					.withRTilde(rTilde)
					.withSTilde(sTilde)
					.build();
		}
	}

}
