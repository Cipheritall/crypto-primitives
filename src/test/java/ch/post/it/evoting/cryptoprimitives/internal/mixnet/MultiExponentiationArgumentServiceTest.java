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

import static ch.post.it.evoting.cryptoprimitives.internal.mixnet.TestMultiExponentiationStatementWitnessPairGenerator.StatementWitnessPair;
import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
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

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationArgument;
import ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationStatement;
import ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationWitness;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.Generators;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;
import ch.post.it.evoting.cryptoprimitives.utils.VerificationResult;

class MultiExponentiationArgumentServiceTest extends TestGroupSetup {

	private static final int COMMITMENT_KEY_SIZE = 11;
	public static final ZqElement zqTwo = ZqElement.create(2, zqGroup);
	public static final ZqElement zqOne = ZqElement.create(1, zqGroup);
	private static MultiExponentiationArgumentService argumentService;
	private static TestMultiExponentiationStatementGenerator statementGenerator;
	private static TestMultiExponentiationWitnessGenerator witnessGenerator;
	private static ElGamalMultiRecipientPublicKey publicKey;
	private static ElGamalGenerator elGamalGenerator;
	private static CommitmentKey commitmentKey;
	private static TestMultiExponentiationStatementWitnessPairGenerator statementWitnessPairGenerator;
	private static RandomService randomService;
	private static TestMultiExponentiationArgumentGenerator argumentGenerator;
	private static HashService hashService;
	private static int publicKeySize;
	private int n;
	private int m;
	private int l;

	@BeforeAll
	static void setUpAll() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		publicKeySize = secureRandom.nextInt(10) + 1;
		publicKey = elGamalGenerator.genRandomPublicKey(publicKeySize);

		final TestCommitmentKeyGenerator commitmentKeyGenerator = new TestCommitmentKeyGenerator(gqGroup);
		commitmentKey = commitmentKeyGenerator.genCommitmentKey(COMMITMENT_KEY_SIZE);
		randomService = new RandomService();

		hashService = TestHashService.create(gqGroup.getQ());
		argumentService = new MultiExponentiationArgumentService(publicKey, commitmentKey, randomService, hashService);

		statementGenerator = new TestMultiExponentiationStatementGenerator(gqGroup);
		witnessGenerator = new TestMultiExponentiationWitnessGenerator(zqGroup);
		statementWitnessPairGenerator = new TestMultiExponentiationStatementWitnessPairGenerator(gqGroup, argumentService, commitmentKey);

		argumentGenerator = new TestMultiExponentiationArgumentGenerator(gqGroup);
	}

	@BeforeEach
	void setup() {
		n = secureRandom.nextInt(COMMITMENT_KEY_SIZE - 1) + 1;
		m = secureRandom.nextInt(COMMITMENT_KEY_SIZE - 1) + 1;
		l = secureRandom.nextInt(publicKeySize) + 1;
	}

	////////// Utilities
	private void assertThrowsIllegalArgumentExceptionWithMessage(String errorMsg, Executable executable) {
		Exception exception = assertThrows(IllegalArgumentException.class, executable);
		assertEquals(errorMsg, exception.getMessage());
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
		void hashServiceWithTooLongHashLengthThrows() {
			HashService otherHashService = HashService.getInstance();
			assertThrowsIllegalArgumentExceptionWithMessage("The hash service's bit length must be smaller than the bit length of q.",
					() -> new MultiExponentiationArgumentService(publicKey, commitmentKey, randomService, otherHashService));
		}

		@Test
		void publicKeyAndCommitmentKeyFromDifferentGroupsThrows() {
			TestCommitmentKeyGenerator otherGenerator = new TestCommitmentKeyGenerator(otherGqGroup);
			CommitmentKey otherKey = otherGenerator.genCommitmentKey(COMMITMENT_KEY_SIZE);
			assertThrowsIllegalArgumentExceptionWithMessage("The public key and commitment key must belong to the same group",
					() -> new MultiExponentiationArgumentService(publicKey, otherKey, randomService, hashService));
		}

		@Test
		void testStatementAndWitnessOfGroupsOfDifferentOrderThrows() {
			TestMultiExponentiationWitnessGenerator otherGroupWitnessGenerator = new TestMultiExponentiationWitnessGenerator(otherZqGroup);
			MultiExponentiationWitness otherWitness = otherGroupWitnessGenerator.genRandomWitness(n, m);
			assertThrowsIllegalArgumentExceptionWithMessage("The witness must belong to a ZqGroup of order q.",
					() -> argumentService.getMultiExponentiationArgument(randomStatement, otherWitness));
		}

		@Test
		void testStatementAndKeysOfDifferentOrderThrows() {
			TestMultiExponentiationStatementGenerator otherStatementGenerator = new TestMultiExponentiationStatementGenerator(otherGqGroup);
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
		void testExponentsMatrixNSizeNotSmallerThanCommitmentKeySizeThrows() {
			int n = COMMITMENT_KEY_SIZE + 1;
			MultiExponentiationStatement statement = statementGenerator.genRandomStatement(n, m, l);
			MultiExponentiationWitness witness = witnessGenerator.genRandomWitness(n, m);
			assertThrowsIllegalArgumentExceptionWithMessage(
					"The number of rows of matrix A must be smaller or equal to the size of the commitment key.",
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

			ElGamalMultiRecipientCiphertext computedC = statement.get_C();
			ElGamalMultiRecipientCiphertext differentC = Generators.genWhile(
					() -> elGamalGenerator.genRandomCiphertext(l), ciphertext -> ciphertext.equals(computedC));
			MultiExponentiationStatement statementWithInvalidC = new MultiExponentiationStatement(
					statement.get_C_matrix(), differentC, statement.get_c_A());

			assertThrowsIllegalArgumentExceptionWithMessage(
					"The computed multi exponentiation ciphertext does not correspond to the one provided in the statement.",
					() -> argumentService.getMultiExponentiationArgument(statementWithInvalidC, witness));
		}

		@Test
		void testCommitmentCAIsNotCommitmentOfMatrixAThrows() {
			StatementWitnessPair statementWitnessPair = statementWitnessPairGenerator.genPair(n, m, l);
			MultiExponentiationStatement statement = statementWitnessPair.getStatement();
			MultiExponentiationWitness witness = statementWitnessPair.getWitness();

			GroupVector<GqElement, GqGroup> computeCommitmentToA = statement.get_c_A();
			GqElement firstElement = computeCommitmentToA.get(0);
			GqElement differentFirstElement = Generators.genWhile(gqGroupGenerator::genMember, element -> element.equals(firstElement));

			GroupVector<GqElement, GqGroup> differentCommitmentToA =
					Stream.concat(
							Stream.of(differentFirstElement),
							computeCommitmentToA
									.stream()
									.skip(1)
					).collect(toGroupVector());
			MultiExponentiationStatement invalidStatement = new MultiExponentiationStatement(
					statement.get_C_matrix(), statement.get_C(), differentCommitmentToA);

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
			int l = COMMITMENT_KEY_SIZE + 1;
			MultiExponentiationStatement statement = statementGenerator.genRandomStatement(n, m, l);
			MultiExponentiationWitness witness = witnessGenerator.genRandomWitness(n, m);
			assertThrowsIllegalArgumentExceptionWithMessage("The ciphertexts must be smaller than the public key.",
					() -> argumentService.getMultiExponentiationArgument(statement, witness));
		}
	}

	@Nested
	@DisplayName("verifyMultiExponentiationArgument...")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VerifyMultiExponentiationArgument {
		private MultiExponentiationArgument randomArgument;
		private MultiExponentiationArgument validArgument;
		private MultiExponentiationStatement validStatement;
		private MultiExponentiationArgument.Builder argumentBuilder;

		@BeforeEach
		void setup() {
			randomArgument = argumentGenerator.genRandomArgument(n, m, l);
			final StatementWitnessPair statementWitnessPair = statementWitnessPairGenerator.genPair(n, m, l);
			validStatement = statementWitnessPair.getStatement();
			validArgument = argumentService.getMultiExponentiationArgument(validStatement, statementWitnessPair.getWitness());
			argumentBuilder = new MultiExponentiationArgument.Builder()
					.with_c_A_0(validArgument.getc_A_0())
					.with_c_B(validArgument.get_c_B())
					.with_E(validArgument.get_E())
					.with_a(validArgument.get_a())
					.with_r(validArgument.get_r())
					.with_b(validArgument.get_b())
					.with_s(validArgument.get_s())
					.with_tau(validArgument.get_tau());
		}

		@Test
		void testValidGeneratedValues() {
			final VerificationResult verificationResult = argumentService.verifyMultiExponentiationArgument(validStatement, validArgument).verify();
			assertTrue(verificationResult.isVerified());
		}

		@Test
		void testNullValuesThrows() {
			assertAll(
					() -> assertThrows(NullPointerException.class, () -> argumentService.verifyMultiExponentiationArgument(null, randomArgument)),
					() -> assertThrows(NullPointerException.class,
							() -> argumentService.verifyMultiExponentiationArgument(statementGenerator.genRandomStatement(n, m, l), null))
			);
		}

		@Test
		void testStatmentAndArgumentFromDifferentGroupsThrows() {
			MultiExponentiationStatement otherStatement = new TestMultiExponentiationStatementGenerator(otherGqGroup).genRandomStatement(n, m, l);
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
			assertTrue(argumentService.verifyMultiExponentiationArgument(statement, argument).verify().isVerified());
		}

		@Test
		void testStatementWithModified_C_ElementDoesNotVerify() {
			GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> modifiedCMatrix = GroupMatrix.fromRows(
					validStatement.get_C_matrix().rowStream().map(r -> r.stream().map(c -> c.getCiphertextExponentiation(
							zqTwo)).collect(Collectors.toList())).collect(Collectors.toList()));
			MultiExponentiationStatement modifiedStatement = new MultiExponentiationStatement(
					modifiedCMatrix,
					validStatement.get_C(),
					validStatement.get_c_A()
			);
			final VerificationResult verificationResult = argumentService.verifyMultiExponentiationArgument(modifiedStatement, validArgument)
					.verify();
			assertFalse(verificationResult.isVerified());
		}

		@Test
		void testStatementWithModified_C_DoesNotVerify() {
			ElGamalMultiRecipientCiphertext modifiedC = validStatement.get_C().getCiphertextExponentiation(zqTwo);
			final MultiExponentiationStatement modifiedStatement = new MultiExponentiationStatement(
					validStatement.get_C_matrix(),
					modifiedC,
					validStatement.get_c_A()
			);
			final VerificationResult verificationResult = argumentService.verifyMultiExponentiationArgument(modifiedStatement, validArgument)
					.verify();
			assertFalse(verificationResult.isVerified());
			assertEquals("E_m must equal C.", verificationResult.getErrorMessages().getFirst());
		}

		@Test
		void testStatementWithModified_cA_ElementDoesNotVerify() {
			final GroupVector<GqElement, GqGroup> modifiedC_a = validStatement.get_c_A().stream()
					.map(GqElement::invert)
					.collect(toGroupVector());
			final MultiExponentiationStatement modifiedStatement = new MultiExponentiationStatement(validStatement.get_C_matrix(),
					validStatement.get_C(), modifiedC_a);
			final VerificationResult verificationResult = argumentService
					.verifyMultiExponentiationArgument(modifiedStatement, validArgument).verify();
			assertFalse(verificationResult.isVerified());
		}

		@Test
		void testArgumentWithModified_cA0_ElementDoesNotVerify() {
			final GqElement modifiedC_A_0 = validArgument.getc_A_0().multiply(GqElementFactory.fromSquareRoot(BigInteger.TWO, gqGroup));
			argumentBuilder.with_c_A_0(modifiedC_A_0);
			final VerificationResult verificationResult = argumentService
					.verifyMultiExponentiationArgument(validStatement, argumentBuilder.build())
					.verify();
			assertFalse(verificationResult.isVerified());
		}

		@Test
		void testArgumentWithModified_cB_ElementDoesNotVerify() {
			argumentBuilder.with_c_B(
					validArgument.get_c_B().stream().map(GqElement::invert).collect(toGroupVector()));
			final VerificationResult verificationResult = argumentService
					.verifyMultiExponentiationArgument(validStatement, argumentBuilder.build())
					.verify();
			assertFalse(verificationResult.isVerified());
		}

		@Test
		void testArgumentWithModified_E_ElementDoesNotVerify() {
			argumentBuilder.with_E(
					validArgument.get_E().stream().map(e -> e.getCiphertextExponentiation(zqTwo)).collect(toGroupVector()));
			final VerificationResult verificationResult = argumentService
					.verifyMultiExponentiationArgument(validStatement, argumentBuilder.build())
					.verify();
			assertFalse(verificationResult.isVerified());
		}

		@Test
		void testArgumentWithModified_a_ElementDoesNotVerify() {
			argumentBuilder.with_a(validArgument.get_a().stream().map(e -> e.add(zqOne)).collect(toGroupVector()));
			final VerificationResult verificationResult = argumentService
					.verifyMultiExponentiationArgument(validStatement, argumentBuilder.build())
					.verify();
			assertFalse(verificationResult.isVerified());
		}

		@Test
		void testArgumentWithModified_r_DoesNotVerify() {
			argumentBuilder.with_r(validArgument.get_r().add(zqOne));
			final VerificationResult verificationResult = argumentService
					.verifyMultiExponentiationArgument(validStatement, argumentBuilder.build())
					.verify();
			assertFalse(verificationResult.isVerified());
		}

		@Test
		void testArgumentWithModified_b_ElementDoesNotVerify() {
			argumentBuilder.with_b(validArgument.get_b().add(zqOne));
			final VerificationResult verificationResult = argumentService
					.verifyMultiExponentiationArgument(validStatement, argumentBuilder.build())
					.verify();
			assertFalse(verificationResult.isVerified());
		}

		@Test
		void testArgumentWithModified_s_DoesNotVerify() {
			argumentBuilder.with_s(validArgument.get_s().add(zqOne));
			final VerificationResult verificationResult = argumentService
					.verifyMultiExponentiationArgument(validStatement, argumentBuilder.build())
					.verify();
			assertFalse(verificationResult.isVerified());
		}

		@Test
		void testArgumentWithModified_tau_DoesNotVerify() {
			argumentBuilder.with_tau(validArgument.get_tau().add(zqOne));
			final VerificationResult verificationResult = argumentService
					.verifyMultiExponentiationArgument(validStatement, argumentBuilder.build())
					.verify();
			assertFalse(verificationResult.isVerified());
		}

		@ParameterizedTest(name = "{5}")
		@MethodSource("verifyMultiExponentiationArgumentRealValueProvider")
		@DisplayName("with real values gives expected result")
		void verifyRealValues(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey,
				final MultiExponentiationStatement statement, final MultiExponentiationArgument argument, final boolean expectedOutput,
				final String description) {

			final HashService hashService = HashService.getInstance();

			final MultiExponentiationArgumentService service = new MultiExponentiationArgumentService(publicKey, commitmentKey, randomService,
					hashService);

			assertEquals(expectedOutput, service.verifyMultiExponentiationArgument(statement, argument).verify().isVerified(),
					String.format("assertion failed for: %s", description));
		}

		Stream<Arguments> verifyMultiExponentiationArgumentRealValueProvider() {
			final List<TestParameters> parametersList = TestParameters.fromResource("/mixnet/verify-multiexp-argument.json");

			return parametersList.stream().parallel().map(testParameters -> {
				// TestContextParser.
				final JsonData contextData = testParameters.getContext();
				final TestContextParser context = new TestContextParser(contextData);
				final GqGroup realGqGroup = context.getGqGroup();

				final ElGamalMultiRecipientPublicKey publicKey = context.parsePublicKey();
				final CommitmentKey commitmentKey = context.parseCommitmentKey();

				// Inputs.
				final JsonData input = testParameters.getInput();
				final JsonData statement = input.getJsonData("statement");
				final TestArgumentParser TestArgumentParser = new TestArgumentParser(realGqGroup);

				final MultiExponentiationArgument multiExpArgument = TestArgumentParser
						.parseMultiExponentiationArgument(input.getJsonData("argument"));
				final MultiExponentiationStatement multiExpStatement = parseMultiExpStatement(realGqGroup, statement, TestArgumentParser);

				// Output.
				final JsonData output = testParameters.getOutput();
				final boolean outputValue = Boolean.parseBoolean(output.toString());

				return Arguments.of(publicKey, commitmentKey, multiExpStatement, multiExpArgument, outputValue, testParameters.getDescription());
			});
		}

		private MultiExponentiationStatement parseMultiExpStatement(final GqGroup realGqGroup, final JsonData statement,
				final TestArgumentParser TestArgumentParser) {

			final GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> ciphertextMatrix = TestArgumentParser
					.parseCiphertextMatrix(statement.getJsonData("ciphertexts"));

			final ElGamalMultiRecipientCiphertext ciphertextC = TestArgumentParser.parseCiphertext(statement.getJsonData("ciphertext_product"));

			final BigInteger[] commitmentAValues = statement.get("c_a", BigInteger[].class);
			final GroupVector<GqElement, GqGroup> commitmentA = Arrays.stream(commitmentAValues)
					.map(bi -> GqElementFactory.fromValue(bi, realGqGroup))
					.collect(toGroupVector());

			return new MultiExponentiationStatement(ciphertextMatrix, ciphertextC, commitmentA);
		}

	}
}
