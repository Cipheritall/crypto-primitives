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

import static ch.post.it.evoting.cryptoprimitives.GroupVector.toSameGroupVector;
import static ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationStatementWitnessPairGenerator.StatementWitnessPair;
import static ch.post.it.evoting.cryptoprimitives.test.tools.GroupVectors.with;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.Generators;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

class MultiExponentiationArgumentServiceTest extends TestGroupSetup {

	private static final int KEY_ELEMENTS_NUMBER = 11;
	private static MultiExponentiationArgumentService argumentService;
	private static MultiExponentiationStatementGenerator statementGenerator;
	private static MultiExponentiationWitnessGenerator witnessGenerator;
	private static ElGamalMultiRecipientPublicKey publicKey;
	private static ElGamalGenerator elGamalGenerator;
	private static CommitmentKey commitmentKey;
	private static MultiExponentiationStatementWitnessPairGenerator statementWitnessPairGenerator;
	private static RandomService randomService;
	private static CommitmentKeyGenerator commitmentKeyGenerator;
	private static MultiExponentiationArgumentGenerator argumentGenerator;
	private static MixnetHashService hashService;
	private int n;
	private int m;
	private int l;

	@BeforeAll
	static void setUpAll() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		publicKey = elGamalGenerator.genRandomPublicKey(KEY_ELEMENTS_NUMBER);

		commitmentKeyGenerator = new CommitmentKeyGenerator(gqGroup);
		commitmentKey = commitmentKeyGenerator.genCommitmentKey(KEY_ELEMENTS_NUMBER);
		randomService = new RandomService();

		hashService = TestHashService.create(gqGroup.getQ());
		argumentService = new MultiExponentiationArgumentService(publicKey, commitmentKey, randomService, hashService);

		statementGenerator = new MultiExponentiationStatementGenerator(gqGroup);
		witnessGenerator = new MultiExponentiationWitnessGenerator(zqGroup);
		statementWitnessPairGenerator = new MultiExponentiationStatementWitnessPairGenerator(gqGroup, argumentService, commitmentKey);

		argumentGenerator = new MultiExponentiationArgumentGenerator(gqGroup);
	}

	@BeforeEach
	void setup() {
		n = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;
		m = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;
		l = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;
	}

	@Nested
	@DisplayName("getMultiExponentiationArgument...")
	class GetMultiExponentiationArgument {
		private MultiExponentiationStatement randomStatement;
		private MultiExponentiationWitness randomWitness;

		@BeforeEach
		void setup() {
			randomStatement = statementGenerator.genRandomStatement(n, m, l);
			randomWitness = witnessGenerator.genRandomWitness(n, m);
		}

		@Test
		void constructorDoesntAcceptNullValues() {
			assertAll(
					() -> assertThrows(NullPointerException.class,
							() -> new MultiExponentiationArgumentService(null, commitmentKey, randomService, hashService)),
					() -> assertThrows(NullPointerException.class,
							() -> new MultiExponentiationArgumentService(publicKey, null, randomService, hashService)),
					() -> assertThrows(NullPointerException.class,
							() -> new MultiExponentiationArgumentService(publicKey, commitmentKey, null, hashService)),
					() -> assertThrows(NullPointerException.class,
							() -> new MultiExponentiationArgumentService(publicKey, commitmentKey, randomService, null))
			);
		}

		@Test
		void publicKeyAndCommitmentKeyFromDifferentGroupsThrows() {
			CommitmentKeyGenerator otherGenerator = new CommitmentKeyGenerator(otherGqGroup);
			CommitmentKey otherKey = otherGenerator.genCommitmentKey(KEY_ELEMENTS_NUMBER);
			assertThrowsIllegalArgumentExceptionWithMessage("The public key and commitment key must belong to the same group",
					() -> new MultiExponentiationArgumentService(publicKey, otherKey, randomService, hashService));
		}

		@Test
		void testStatementAndWitnessOfGroupsOfDifferentOrderThrows() {
			MultiExponentiationWitnessGenerator otherGroupWitnessGenerator = new MultiExponentiationWitnessGenerator(otherZqGroup);
			MultiExponentiationWitness otherWitness = otherGroupWitnessGenerator.genRandomWitness(n, m);
			assertThrowsIllegalArgumentExceptionWithMessage("The witness must belong to a ZqGroup of order q.",
					() -> argumentService.getMultiExponentiationArgument(randomStatement, otherWitness));
		}

		@Test
		void testStatementAndKeysOfDifferentOrderThrows() {
			MultiExponentiationStatementGenerator otherStatementGenerator = new MultiExponentiationStatementGenerator(otherGqGroup);
			MultiExponentiationStatement otherGroupStatement = otherStatementGenerator.genRandomStatement(n, m, l);
			assertThrowsIllegalArgumentExceptionWithMessage("The statement must belong to the same group as the public key and commitment key.",
					() -> argumentService.getMultiExponentiationArgument(otherGroupStatement, randomWitness));
		}

		@Test
		void testStatementAndWitnessWithDifferentMThrows() {
			MultiExponentiationStatement statement = statementGenerator.genRandomStatement(n, m, l);
			MultiExponentiationWitness witness = witnessGenerator.genRandomWitness(n, m + 1);
			assertThrowsIllegalArgumentExceptionWithMessage("Statement and witness do not have compatible m dimension.",
					() -> argumentService.getMultiExponentiationArgument(statement, witness));
		}

		@Test
		void testStatementAndWitnessWithDifferentNThrows() {
			MultiExponentiationStatement statement = statementGenerator.genRandomStatement(n, m, l);
			MultiExponentiationWitness witness = witnessGenerator.genRandomWitness(n + 1, m);
			assertThrowsIllegalArgumentExceptionWithMessage("Statement and witness do not have compatible n dimension.",
					() -> argumentService.getMultiExponentiationArgument(statement, witness));
		}

		@Test
		void testExponentsMatrixNSizeNotSmallerThanKeySizeThrows() {
			int n = KEY_ELEMENTS_NUMBER + 1;
			MultiExponentiationStatement statement = statementGenerator.genRandomStatement(n, m, l);
			MultiExponentiationWitness witness = witnessGenerator.genRandomWitness(n, m);
			assertThrowsIllegalArgumentExceptionWithMessage("The number of rows of matrix A must be less than the size of the public key.",
					() -> argumentService.getMultiExponentiationArgument(statement, witness));
		}

		@Test
		void testNullValuesThrows() {
			assertAll(
					() -> assertThrows(NullPointerException.class, () -> argumentService.getMultiExponentiationArgument(null, randomWitness)),
					() -> assertThrows(NullPointerException.class, () -> argumentService.getMultiExponentiationArgument(randomStatement, null))
			);
		}

		@Test
		void testCIsNotMultiExponentiationProductThrows() {
			StatementWitnessPair statementWitnessPair = statementWitnessPairGenerator.genPair(n, m, l);
			MultiExponentiationStatement statement = statementWitnessPair.getStatement();
			MultiExponentiationWitness witness = statementWitnessPair.getWitness();

			ElGamalMultiRecipientCiphertext computedC = statement.getC();
			ElGamalMultiRecipientCiphertext differentC = Generators.genWhile(
					() -> elGamalGenerator.genRandomCiphertext(l), ciphertext -> ciphertext.equals(computedC));
			MultiExponentiationStatement statementWithInvalidC = new MultiExponentiationStatement(
					statement.getCMatrix(), differentC, statement.getcA());

			assertThrowsIllegalArgumentExceptionWithMessage(
					"The computed multi exponentiation ciphertext does not correspond to the one provided in the statement.",
					() -> argumentService.getMultiExponentiationArgument(statementWithInvalidC, witness));
		}

		@Test
		void testCommitmentCAIsNotCommitmentOfMatrixAThrows() {
			StatementWitnessPair statementWitnessPair = statementWitnessPairGenerator.genPair(n, m, l);
			MultiExponentiationStatement statement = statementWitnessPair.getStatement();
			MultiExponentiationWitness witness = statementWitnessPair.getWitness();

			GroupVector<GqElement, GqGroup> computeCommitmentToA = statement.getcA();
			GqElement firstElement = computeCommitmentToA.get(0);
			GqElement differentFirstElement = Generators.genWhile(gqGroupGenerator::genMember, element -> element.equals(firstElement));

			GroupVector<GqElement, GqGroup> differentCommitmentToA =
					Stream.concat(
							Stream.of(differentFirstElement),
							computeCommitmentToA
									.stream()
									.skip(1)
					).collect(toSameGroupVector());
			MultiExponentiationStatement invalidStatement = new MultiExponentiationStatement(
					statement.getCMatrix(), statement.getC(), differentCommitmentToA);

			assertThrowsIllegalArgumentExceptionWithMessage("The commitment provided does not correspond to the matrix A.",
					() -> argumentService.getMultiExponentiationArgument(invalidStatement, witness));
		}

		@Test
		void sanityCheck() {
			MultiExponentiationArgumentService argumentService = new MultiExponentiationArgumentService(
					publicKey, commitmentKey, randomService, hashService);
			StatementWitnessPair pair = statementWitnessPairGenerator.genPair(n, m, l);
			MultiExponentiationStatement statement = pair.getStatement();
			MultiExponentiationWitness witness = pair.getWitness();
			assertDoesNotThrow(() -> argumentService.getMultiExponentiationArgument(statement, witness));
		}

		@Test
		void testThatLongerCiphertextsThanKeyThrows() {
			int l = KEY_ELEMENTS_NUMBER + 1;
			MultiExponentiationStatement statement = statementGenerator.genRandomStatement(n, m, l);
			MultiExponentiationWitness witness = witnessGenerator.genRandomWitness(n, m);
			assertThrowsIllegalArgumentExceptionWithMessage("The ciphertexts must be smaller than the public key.",
					() -> argumentService.getMultiExponentiationArgument(statement, witness));
		}

		@Test
		void testWithSpecificValuesReturnsExpectedResult() {
			SpecificValues values = new SpecificValues();
			MultiExponentiationArgumentService service = values.createMultiExponentiationService();
			MultiExponentiationArgument computed = service.getMultiExponentiationArgument(values.createStatement(), values.createWitness());

			assertEquals(values.createArgument(), computed);
			assertTrue(service.verifyMultiExponentiationArgument(values.createStatement(), values.createArgument()));
		}
	}

	@Nested
	@DisplayName("verifyMultiExponentiationArgument...")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VerifyMultiExponentiationArgument {
		private MultiExponentiationArgument randomArgument;

		@BeforeEach
		void setup() {
			randomArgument = argumentGenerator.genRandomArgument(n, m, l);
		}

		@Test
		void testNullValuesThrows() {
			assertAll(
					() -> assertThrows(NullPointerException.class, () -> argumentService.verifyMultiExponentiationArgument(null, randomArgument)),
					() -> assertThrows(NullPointerException.class, () -> argumentService.verifyMultiExponentiationArgument(null, randomArgument))
			);
		}

		@Test
		void testStatementAndArgumentFromDifferentGroupsThrows() {
			MultiExponentiationStatement otherStatement = new MultiExponentiationStatementGenerator(otherGqGroup).genRandomStatement(n, m, l);
			assertThrowsIllegalArgumentExceptionWithMessage("Statement and argument must belong to the same group.",
					() -> argumentService.verifyMultiExponentiationArgument(otherStatement, randomArgument));
		}

		@Test
		void testStatementAndArgumentWithDifferentNThrows() {
			final MultiExponentiationStatement otherStatement = statementGenerator.genRandomStatement(n + 1, m, l);
			assertThrowsIllegalArgumentExceptionWithMessage("n dimension doesn't match.",
					() -> argumentService.verifyMultiExponentiationArgument(otherStatement, randomArgument));
		}

		@Test
		void testStatementAndArgumentWithDifferentMThrows() {
			final MultiExponentiationStatement otherStatement = statementGenerator.genRandomStatement(n, m + 1, l);
			assertThrowsIllegalArgumentExceptionWithMessage("m dimension doesn't match.",
					() -> argumentService.verifyMultiExponentiationArgument(otherStatement, randomArgument));
		}

		@Test
		void testStatementAndArgumentWithDifferentLThrows() {
			final MultiExponentiationStatement otherStatement = statementGenerator.genRandomStatement(n, m, l + 1);
			assertThrowsIllegalArgumentExceptionWithMessage("l dimension doesn't match.",
					() -> argumentService.verifyMultiExponentiationArgument(otherStatement, randomArgument));
		}

		@Test
		void testArgumentGenerationAndVerificationIsVerified() {
			StatementWitnessPair pair = statementWitnessPairGenerator.genPair(n, m, l);
			MultiExponentiationStatement statement = pair.getStatement();
			MultiExponentiationWitness witness = pair.getWitness();
			MultiExponentiationArgument argument = argumentService.getMultiExponentiationArgument(statement, witness);
			assertTrue(argumentService.verifyMultiExponentiationArgument(statement, argument));
		}

		@Test
		void testStatementWithModified_C_ElementDoesNotVerify() {
			SpecificValues values = new SpecificValues();
			values.ciphertextMatrix = with(values.ciphertextMatrix, 0, 0, values.c1);
			MultiExponentiationArgumentService service = values.createMultiExponentiationService();
			assertFalse(service.verifyMultiExponentiationArgument(values.createStatement(), values.createArgument()));
		}

		@Test
		void testStatementWithModified_C_DoesNotVerify() {
			SpecificValues values = new SpecificValues();
			values.ciphertext = ElGamalMultiRecipientCiphertext.create(values.gNine, Arrays.asList(values.gThirteen, values.gThirteen, values.gOne));
			MultiExponentiationArgumentService service = values.createMultiExponentiationService();
			assertFalse(service.verifyMultiExponentiationArgument(values.createStatement(), values.createArgument()));
		}

		@Test
		void testStatementWithModified_cA_ElementDoesNotVerify() {
			SpecificValues values = new SpecificValues();
			values.ca = with(values.ca, 1, values.gNine);
			MultiExponentiationArgumentService service = values.createMultiExponentiationService();
			assertFalse(service.verifyMultiExponentiationArgument(values.createStatement(), values.createArgument()));
		}

		@Test
		void testArgumentWithModified_cA0_ElementDoesNotVerify() {
			SpecificValues values = new SpecificValues();
			values.cA0 = values.gEight;
			MultiExponentiationArgumentService service = values.createMultiExponentiationService();
			assertFalse(service.verifyMultiExponentiationArgument(values.createStatement(), values.createArgument()));
		}

		@Test
		void testArgumentWithModified_cB_ElementDoesNotVerify() {
			SpecificValues values = new SpecificValues();
			values.cB = with(values.cB, 0, values.gOne);
			MultiExponentiationArgumentService service = values.createMultiExponentiationService();
			assertFalse(service.verifyMultiExponentiationArgument(values.createStatement(), values.createArgument()));
		}

		@Test
		void testArgumentWithModified_E_ElementDoesNotVerify() {
			SpecificValues values = new SpecificValues();
			values.eVector = with(values.eVector, 0, values.e1);
			MultiExponentiationArgumentService service = values.createMultiExponentiationService();
			assertFalse(service.verifyMultiExponentiationArgument(values.createStatement(), values.createArgument()));
		}

		@Test
		void testArgumentWithModified_a_ElementDoesNotVerify() {
			SpecificValues values = new SpecificValues();
			values.aVector = with(values.aVector, 0, values.zEight);
			MultiExponentiationArgumentService service = values.createMultiExponentiationService();
			assertFalse(service.verifyMultiExponentiationArgument(values.createStatement(), values.createArgument()));
		}

		@Test
		void testArgumentWithModified_r_DoesNotVerify() {
			SpecificValues values = new SpecificValues();
			values.r = values.zFour;
			MultiExponentiationArgumentService service = values.createMultiExponentiationService();
			assertFalse(service.verifyMultiExponentiationArgument(values.createStatement(), values.createArgument()));
		}

		@Test
		void testArgumentWithModified_b_ElementDoesNotVerify() {
			SpecificValues values = new SpecificValues();
			values.b = values.zFour;
			MultiExponentiationArgumentService service = values.createMultiExponentiationService();
			assertFalse(service.verifyMultiExponentiationArgument(values.createStatement(), values.createArgument()));
		}

		@Test
		void testArgumentWithModified_s_DoesNotVerify() {
			SpecificValues values = new SpecificValues();
			values.s = values.zFour;
			MultiExponentiationArgumentService service = values.createMultiExponentiationService();
			assertFalse(service.verifyMultiExponentiationArgument(values.createStatement(), values.createArgument()));
		}

		@Test
		void testArgumentWithModified_tau_DoesNotVerify() {
			SpecificValues values = new SpecificValues();
			values.tau = values.zFour;
			MultiExponentiationArgumentService service = values.createMultiExponentiationService();
			assertFalse(service.verifyMultiExponentiationArgument(values.createStatement(), values.createArgument()));
		}

		@ParameterizedTest(name = "{5}")
		@MethodSource("verifyMultiExponentiationArgumentRealValueProvider")
		@DisplayName("with real values gives expected result")
		void verifyRealValues(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey,
				final MultiExponentiationStatement statement, final MultiExponentiationArgument argument, final boolean expectedOutput,
				final String description) throws NoSuchAlgorithmException {

			final HashService hashService = new HashService(MessageDigest.getInstance("SHA-256"));
			final MixnetHashService mixnetHashService = new MixnetHashService(hashService, publicKey.getGroup().getQ().bitLength());

			final MultiExponentiationArgumentService service = new MultiExponentiationArgumentService(publicKey, commitmentKey, randomService,
					mixnetHashService);

			assertEquals(expectedOutput, service.verifyMultiExponentiationArgument(statement, argument),
					String.format("assertion failed for: %s", description));
		}

		Stream<Arguments> verifyMultiExponentiationArgumentRealValueProvider() {
			final List<TestParameters> parametersList = TestParameters.fromResource("/mixnet/verify-multiexp-argument.json");

			return parametersList.stream().parallel().map(testParameters -> {
				// Context.
				final JsonData contextData = testParameters.getContext();
				final Context context = new Context(contextData);
				final GqGroup realGqGroup = context.getGqGroup();

				final ElGamalMultiRecipientPublicKey publicKey = context.parsePublicKey();
				final CommitmentKey commitmentKey = context.parseCommitmentKey();

				// Inputs.
				final JsonData input = testParameters.getInput();
				final JsonData statement = input.getJsonData("statement");
				final ArgumentParser argumentParser = new ArgumentParser(realGqGroup);

				final MultiExponentiationArgument multiExpArgument = argumentParser.parseMultiExponentiationArgument(input.getJsonData("argument"));
				final MultiExponentiationStatement multiExpStatement = parseMultiExpStatement(realGqGroup, statement, argumentParser);

				// Output.
				final JsonData output = testParameters.getOutput();
				final boolean outputValue = output.get("verif_result", Boolean.class);

				return Arguments.of(publicKey, commitmentKey, multiExpStatement, multiExpArgument, outputValue, testParameters.getDescription());
			});
		}

		private MultiExponentiationStatement parseMultiExpStatement(final GqGroup realGqGroup, final JsonData statement,
				final ArgumentParser argumentParser) {

			final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> ciphertextMatrix = argumentParser
					.parseCiphertextMatrix(statement.getJsonData("ciphertexts"));

			final ElGamalMultiRecipientCiphertext ciphertextC = argumentParser.parseCiphertext(statement.getJsonData("ciphertext_product"));

			final BigInteger[] commitmentAValues = statement.get("c_a", BigInteger[].class);
			final GroupVector<GqElement, GqGroup> commitmentA = Arrays.stream(commitmentAValues)
					.map(bi -> GqElement.create(bi, realGqGroup))
					.collect(toSameGroupVector());

			return new MultiExponentiationStatement(ciphertextMatrix, ciphertextC, commitmentA);
		}

	}

	/**
	 * Mutable class used for testing specific values of the algorithm. The initialized values are valid hand computed values of statement, witness
	 * and argument. These can be modified to create invalid states.
	 */
	static class SpecificValues {
		private static final BigInteger ZERO = BigInteger.ZERO;
		private static final BigInteger ONE = BigInteger.ONE;
		private static final BigInteger TWO = BigInteger.valueOf(2);
		private static final BigInteger THREE = BigInteger.valueOf(3);
		private static final BigInteger FOUR = BigInteger.valueOf(4);
		private static final BigInteger FIVE = BigInteger.valueOf(5);
		private static final BigInteger SIX = BigInteger.valueOf(6);
		private static final BigInteger SEVEN = BigInteger.valueOf(7);
		private static final BigInteger EIGHT = BigInteger.valueOf(8);
		private static final BigInteger NINE = BigInteger.valueOf(9);
		private static final BigInteger TEN = BigInteger.valueOf(10);

		//Group values
		BigInteger p = BigInteger.valueOf(23);
		BigInteger q = BigInteger.valueOf(11);
		BigInteger g = BigInteger.valueOf(2);
		GqGroup specificGqGroup = new GqGroup(p, q, g);
		ZqGroup zqGroup = new ZqGroup(q);

		// Create GqElements
		GqElement gOne = specificGqGroup.getIdentity();
		GqElement gTwo = specificGqGroup.getGenerator();
		GqElement gThree = GqElement.create(THREE, specificGqGroup);
		GqElement gFour = GqElement.create(FOUR, specificGqGroup);
		GqElement gSix = GqElement.create(SIX, specificGqGroup);
		GqElement gEight = GqElement.create(EIGHT, specificGqGroup);
		GqElement gNine = GqElement.create(NINE, specificGqGroup);
		GqElement gTwelve = GqElement.create(BigInteger.valueOf(12), specificGqGroup);
		GqElement gThirteen = GqElement.create(BigInteger.valueOf(13), specificGqGroup);
		GqElement gSixteen = GqElement.create(BigInteger.valueOf(16), specificGqGroup);
		GqElement gEighteen = GqElement.create(BigInteger.valueOf(18), specificGqGroup);

		// Create ZqElements
		ZqElement zOne = ZqElement.create(ONE, zqGroup);
		ZqElement zTwo = ZqElement.create(TWO, zqGroup);
		ZqElement zThree = ZqElement.create(THREE, zqGroup);
		ZqElement zFour = ZqElement.create(FOUR, zqGroup);
		ZqElement zFive = ZqElement.create(FIVE, zqGroup);
		ZqElement zSeven = ZqElement.create(SEVEN, zqGroup);
		ZqElement zEight = ZqElement.create(EIGHT, zqGroup);
		ZqElement zNine = ZqElement.create(NINE, zqGroup);

		// Public key values:
		// pk = (8, 13, 4)
		List<GqElement> keyElements = Arrays.asList(gEight, gThirteen, gFour);

		// Commitment key values:
		// ck = {3, (6, 13, 12)}
		GqElement h = gThree;
		ImmutableList<GqElement> gs = ImmutableList.of(gSix, gThirteen, gTwelve);

		// Statement values
		// ciphertext matrix values
		// C0 = [ {1, ( 3, 6,  4)}, { 4, (12, 16, 6)} ]
		// C1 = [ {1, (13, 4, 18)}, {13, ( 2,  3, 1)} ]
		ElGamalMultiRecipientCiphertext c0 = ElGamalMultiRecipientCiphertext.create(gOne, Arrays.asList(gThree, gSix, gFour));
		ElGamalMultiRecipientCiphertext c1 = ElGamalMultiRecipientCiphertext.create(gOne, Arrays.asList(gThirteen, gFour, gEighteen));
		ElGamalMultiRecipientCiphertext c2 = ElGamalMultiRecipientCiphertext.create(gFour, Arrays.asList(gTwelve, gSixteen, gSix));
		ElGamalMultiRecipientCiphertext c3 = ElGamalMultiRecipientCiphertext.create(gThirteen, Arrays.asList(gTwo, gThree, gOne));
		GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> ciphertextMatrix = GroupVector.of(c0, c1, c2, c3).toMatrix(2, 2);
		// Create the ciphertext: C = {9, (4, 13, 1)}
		ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(gNine, Arrays.asList(gFour, gThirteen, gOne));
		// Create the commitment: ca = (8, 18)
		GroupVector<GqElement, GqGroup> ca = GroupVector.of(gEight, gEighteen);

		// Witness values
		// Create the matrix: a1 a2
		//                   [3  5]
		//		 	         [9  1]
		GroupMatrix<ZqElement, ZqGroup> matrixA = GroupVector.of(zThree, zNine, zFive, zOne).toMatrix(2, 2);
		// Create the exponents: r = (7, 8)
		GroupVector<ZqElement, ZqGroup> rVector = GroupVector.of(zSeven, zEight);
		// Create the exponent: rho = 2
		ZqElement rho = zTwo;
		List<BigInteger> randomValues = Arrays.asList(ZERO, ONE, SIX, TWO, THREE, SEVEN, NINE, TEN, ONE, THREE, FOUR, FIVE, SIX, EIGHT, SEVEN);

		// Argument values
		// Argument: cA0 = 1, cB = (12, 4, 1, 8), E = ({2, (13, 2, 2)}, {9, (18, 18, 6)}, {9, (4, 13, 1)}, {6, (8, 3, 6)})
		// a = (2, 4), r = 7, b = 1, s = 5, tau = 5
		GqElement cA0 = gOne;
		GroupVector<GqElement, GqGroup> cB = GroupVector.of(gTwelve, gFour, gOne, gEight);

		ElGamalMultiRecipientCiphertext e0 = ElGamalMultiRecipientCiphertext.create(gTwo, Arrays.asList(gThirteen, gTwo, gTwo));
		ElGamalMultiRecipientCiphertext e1 = ElGamalMultiRecipientCiphertext.create(gNine, Arrays.asList(gEighteen, gEighteen, gSix));
		ElGamalMultiRecipientCiphertext e2 = ElGamalMultiRecipientCiphertext.create(gNine, Arrays.asList(gFour, gThirteen, gOne));
		ElGamalMultiRecipientCiphertext e3 = ElGamalMultiRecipientCiphertext.create(gSix, Arrays.asList(gEight, gThree, gSix));
		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> eVector = GroupVector.of(e0, e1, e2, e3);

		GroupVector<ZqElement, ZqGroup> aVector = GroupVector.of(zTwo, zFour);
		ZqElement b = zOne;
		ZqElement tau = zFive;
		ZqElement s = zFive;
		ZqElement r = zSeven;

		ElGamalMultiRecipientPublicKey getPublicKey() {
			return new ElGamalMultiRecipientPublicKey(keyElements);
		}

		private CommitmentKey getCommitmentKey() {
			return new CommitmentKey(h, gs);
		}

		private RandomService getSpecificRandomService() {
			return new RandomService() {
				final Iterator<BigInteger> values = randomValues.iterator();

				@Override
				public BigInteger genRandomInteger(BigInteger upperBound) {
					return values.next();
				}
			};
		}

		private MultiExponentiationStatement createStatement() {
			return new MultiExponentiationStatement(ciphertextMatrix, ciphertext, ca);
		}

		private MultiExponentiationWitness createWitness() {
			return new MultiExponentiationWitness(matrixA, rVector, rho);
		}

		private MultiExponentiationArgument createArgument() {
			return new MultiExponentiationArgument.Builder()
					.withcA0(cA0)
					.withcBVector(cB)
					.withEVector(eVector)
					.withaVector(aVector)
					.withr(r)
					.withb(b)
					.withs(s)
					.withtau(tau)
					.build();
		}

		private MixnetHashService hashService() {
			return TestHashService.create(q);
		}

		// Create a argument service initialized with this instances' specific values for the public key, the commitment key, the random values and a
		// specific hash service
		MultiExponentiationArgumentService createMultiExponentiationService() {
			return new MultiExponentiationArgumentService(getPublicKey(), getCommitmentKey(),
					getSpecificRandomService(), hashService());
		}
	}

	////////// Utilities
	private void assertThrowsIllegalArgumentExceptionWithMessage(String errorMsg, Executable executable) {
		Exception exception = assertThrows(IllegalArgumentException.class, executable);
		assertEquals(errorMsg, exception.getMessage());
	}
}

