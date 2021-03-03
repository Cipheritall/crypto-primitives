/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.ConversionService.integerToByteArray;
import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;
import static ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationStatementWitnessPairGenerator.StatementWitnessPair;
import static com.google.common.collect.ImmutableList.toImmutableList;
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
import java.util.Arrays;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.stubbing.Answer;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.Hashable;
import ch.post.it.evoting.cryptoprimitives.HashableList;
import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.GroupMatrices;
import ch.post.it.evoting.cryptoprimitives.test.tools.GroupVectors;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.Generators;

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
	private static HashService hashServiceMock;
	private static MultiExponentiationArgumentGenerator argumentGenerator;
	private static HashService delegateHashService;
	private int n;
	private int m;
	private int l;

	@BeforeAll
	static void setUpAll() throws NoSuchAlgorithmException {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		publicKey = elGamalGenerator.genRandomPublicKey(KEY_ELEMENTS_NUMBER);

		commitmentKeyGenerator = new CommitmentKeyGenerator(gqGroup);
		commitmentKey = commitmentKeyGenerator.genCommitmentKey(KEY_ELEMENTS_NUMBER);
		randomService = new RandomService();

		delegateHashService = new HashService(MessageDigest.getInstance("SHA-256"));
		// Mock the hashService in order to have a hash value of length smaller than q (preconditions on hashService)
		hashServiceMock = getHashServiceMock(delegateHashService, gqGroup.getQ());

		argumentService = new MultiExponentiationArgumentService(publicKey, commitmentKey, randomService, hashServiceMock);

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

	@Test
	void testWithSpecificValuesReturnsExpectedResult() {
		// Create groups
		BigInteger p = BigInteger.valueOf(23);
		BigInteger q = BigInteger.valueOf(11);
		BigInteger g = BigInteger.valueOf(2);
		GqGroup specificGqGroup = new GqGroup(p, q, g);
		ZqGroup zqGroup = new ZqGroup(q);

		// Create BigIntegers
		BigInteger ZERO = BigInteger.ZERO;
		BigInteger ONE = BigInteger.ONE;
		BigInteger TWO = BigInteger.valueOf(2);
		BigInteger THREE = BigInteger.valueOf(3);
		BigInteger FOUR = BigInteger.valueOf(4);
		BigInteger FIVE = BigInteger.valueOf(5);
		BigInteger SIX = BigInteger.valueOf(6);
		BigInteger SEVEN = BigInteger.valueOf(7);
		BigInteger EIGHT = BigInteger.valueOf(8);
		BigInteger NINE = BigInteger.valueOf(9);
		BigInteger TEN = BigInteger.valueOf(10);

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

		// Create the public key: pk = (8, 13, 4)
		ElGamalMultiRecipientPublicKey publicKey = new ElGamalMultiRecipientPublicKey(Arrays.asList(gEight, gThirteen, gFour));

		// Create the ciphertext matrix:
		// C0 = [ {1, ( 3, 6,  4)}, { 4, (12, 16, 6)} ]
		// C1 = [ {1, (13, 4, 18)}, {13, ( 2,  3, 1)} ]
		ElGamalMultiRecipientCiphertext c0 = ElGamalMultiRecipientCiphertext.create(gOne, Arrays.asList(gThree, gSix, gFour));
		ElGamalMultiRecipientCiphertext c1 = ElGamalMultiRecipientCiphertext.create(gOne, Arrays.asList(gThirteen, gFour, gEighteen));
		ElGamalMultiRecipientCiphertext c2 = ElGamalMultiRecipientCiphertext.create(gFour, Arrays.asList(gTwelve, gSixteen, gSix));
		ElGamalMultiRecipientCiphertext c3 = ElGamalMultiRecipientCiphertext.create(gThirteen, Arrays.asList(gTwo, gThree, gOne));
		SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> ciphertextMatrix = SameGroupVector.of(c0, c1, c2, c3).toMatrix(2, 2);

		// Create the ciphertext: C = {9, (4, 13, 1)}
		ElGamalMultiRecipientCiphertext ciphertext = ElGamalMultiRecipientCiphertext.create(gNine, Arrays.asList(gFour, gThirteen, gOne));

		// Create the commitment: ca = (8, 18)
		SameGroupVector<GqElement, GqGroup> ca = SameGroupVector.of(gEight, gEighteen);

		// Create the statement
		MultiExponentiationStatement statement = new MultiExponentiationStatement(ciphertextMatrix, ciphertext, ca);

		// Create the matrix: a1 a2
		//                   [3  5]
		//		 	         [9  1]
		SameGroupMatrix<ZqElement, ZqGroup> matrixA = SameGroupVector.of(zThree, zNine, zFive, zOne).toMatrix(2, 2);

		// Create the exponents: r = (7, 8)
		SameGroupVector<ZqElement, ZqGroup> r = SameGroupVector.of(zSeven, zEight);

		// Create the exponent: rho = 2
		ZqElement rho = zTwo;

		// Create the witness
		MultiExponentiationWitness witness = new MultiExponentiationWitness(matrixA, r, rho);

		// Calculate the argument
		// Create ShuffleArgumentService
		// Create the commitment key: ck = {3, (6, 13, 12)}
		CommitmentKey commitmentKey = new CommitmentKey(gThree, ImmutableList.of(gSix, gThirteen, gTwelve));
		RandomService specificRandomService = spy(randomService);
		// Multi: a0 = (0, 1), r0 = 6, b = (2, 3, 7, 9), s = (10, 1, 3, 4), tau = (5, 6, 8, 7)
		doReturn(ZERO, ONE, SIX, TWO, THREE, SEVEN, NINE, TEN, ONE, THREE, FOUR, FIVE, SIX, EIGHT, SEVEN)
				.when(specificRandomService).genRandomInteger(q);
		HashService specificHashService = getHashServiceMock(delegateHashService, specificGqGroup.getQ());

		MultiExponentiationArgumentService service = new MultiExponentiationArgumentService(publicKey, commitmentKey, specificRandomService,
				specificHashService);
		MultiExponentiationArgument actual = service.getMultiExponentiationArgument(statement, witness);

		// Create the expected output
		SameGroupVector<GqElement, GqGroup> cB = SameGroupVector.of(gTwelve, gFour, gOne, gEight);
		SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> eVector = SameGroupVector.of(
				ElGamalMultiRecipientCiphertext.create(gTwo, Arrays.asList(gThirteen, gTwo, gTwo)),
				ElGamalMultiRecipientCiphertext.create(gNine, Arrays.asList(gEighteen, gEighteen, gSix)),
				ElGamalMultiRecipientCiphertext.create(gNine, Arrays.asList(gFour, gThirteen, gOne)),
				ElGamalMultiRecipientCiphertext.create(gSix, Arrays.asList(gEight, gThree, gSix))
		);

		// Argument: cA0 = 1, cB = (12, 4, 1, 8), E = ({2, (13, 2, 2)}, {9, (18, 18, 6)}, {9, (4, 13, 1)}, {6, (8, 3, 6)})
		// a = (2, 4), r = 7, b = 1, s = 5, tau = 5
		MultiExponentiationArgument expected = new MultiExponentiationArgument.Builder()
				.withcA0(gOne)
				.withcBVector(cB)
				.withEVector(eVector)
				.withaVector(SameGroupVector.of(zTwo, zFour))
				.withr(zSeven)
				.withb(zOne)
				.withs(zFive)
				.withtau(zFive)
				.build();

		assertEquals(expected, actual);
	}

	////////// Utilities
	private static void assertThrowsIllegalArgumentExceptionWithMessage(String errorMsg, Executable executable) {
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
							() -> new MultiExponentiationArgumentService(null, commitmentKey, randomService, hashServiceMock)),
					() -> assertThrows(NullPointerException.class,
							() -> new MultiExponentiationArgumentService(publicKey, null, randomService, hashServiceMock)),
					() -> assertThrows(NullPointerException.class,
							() -> new MultiExponentiationArgumentService(publicKey, commitmentKey, null, hashServiceMock)),
					() -> assertThrows(NullPointerException.class,
							() -> new MultiExponentiationArgumentService(publicKey, commitmentKey, randomService, null))
			);
		}

		@Test
		void publicKeyAndCommitmentKeyFromDifferentGroupsThrows() {
			CommitmentKeyGenerator otherGenerator = new CommitmentKeyGenerator(otherGqGroup);
			CommitmentKey otherKey = otherGenerator.genCommitmentKey(KEY_ELEMENTS_NUMBER);
			assertThrowsIllegalArgumentExceptionWithMessage("The public key and commitment key must belong to the same group",
					() -> new MultiExponentiationArgumentService(publicKey, otherKey, randomService, hashServiceMock));
		}

		@Test
		void publicKeyAndCommitmentKeyOfDifferentSizeThrows() {
			CommitmentKey longerKey = commitmentKeyGenerator.genCommitmentKey(KEY_ELEMENTS_NUMBER + 1);
			assertThrowsIllegalArgumentExceptionWithMessage("The commitment key and public key must be of the same size.",
					() -> new MultiExponentiationArgumentService(publicKey, longerKey, randomService, hashServiceMock));
		}

		@Test
		void testStatementAndWitnessOfGroupsOfDifferentOrderThrows() {
			MultiExponentiationWitnessGenerator otherGroupWitnessGenerator = new MultiExponentiationWitnessGenerator(otherZqGroup);
			MultiExponentiationWitness otherWitness = otherGroupWitnessGenerator.genRandomWitness(n, m);
			assertThrowsIllegalArgumentExceptionWithMessage("The witness and argument must belong to groups of the same order.",
					() -> argumentService.getMultiExponentiationArgument(randomStatement, otherWitness));
		}

		@Test
		void testStatementAndKeysOfDifferentOrderThrows() {
			MultiExponentiationStatementGenerator otherStatementGenerator = new MultiExponentiationStatementGenerator(otherGqGroup);
			MultiExponentiationStatement otherGroupStatement = otherStatementGenerator.genRandomStatement(n, m, l);
			assertThrowsIllegalArgumentExceptionWithMessage("The statement and argument must belong to the same group.",
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

			SameGroupVector<GqElement, GqGroup> computeCommitmentToA = statement.getcA();
			GqElement firstElement = computeCommitmentToA.get(0);
			GqElement differentFirstElement = Generators.genWhile(gqGroupGenerator::genMember, element -> element.equals(firstElement));

			SameGroupVector<GqElement, GqGroup> differentCommitmentToA =
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
					publicKey, commitmentKey, randomService, hashServiceMock);
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
	}

	@Nested
	@DisplayName("verifyMultiExponentiationArgument...")
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
		void testStatmentAndArgumentFromDifferentGroupsThrows() {
			MultiExponentiationStatement otherStatement = new MultiExponentiationStatementGenerator(otherGqGroup).genRandomStatement(n, m, l);
			assertThrowsIllegalArgumentExceptionWithMessage("Statement and argument must belong to the same group.",
					() -> argumentService.verifyMultiExponentiationArgument(otherStatement, randomArgument));
		}

		@Test
		void testStatmentAndArgumentWithDifferentNThrows() {
			final MultiExponentiationStatement otherStatement = statementGenerator.genRandomStatement(n + 1, m, l);
			assertThrowsIllegalArgumentExceptionWithMessage("n dimension doesn't match.",
					() -> argumentService.verifyMultiExponentiationArgument(otherStatement, randomArgument));
		}

		@Test
		void testStatmentAndArgumentWithDifferentMThrows() {
			final MultiExponentiationStatement otherStatement = statementGenerator.genRandomStatement(n, m + 1, l);
			assertThrowsIllegalArgumentExceptionWithMessage("m dimension doesn't match.",
					() -> argumentService.verifyMultiExponentiationArgument(otherStatement, randomArgument));
		}

		@Test
		void testStatmentAndArgumentWithDifferentLThrows() {
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
			StatementWitnessPair pair = statementWitnessPairGenerator.genPair(n, m, l);
			MultiExponentiationStatement statement = pair.getStatement();
			MultiExponentiationWitness witness = pair.getWitness();
			MultiExponentiationArgument argument = argumentService.getMultiExponentiationArgument(statement, witness);

			final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix = statement.getCMatrix();
			int i = secureRandom.nextInt(CMatrix.numRows());
			int j = secureRandom.nextInt(CMatrix.numColumns());
			ElGamalMultiRecipientCiphertext element = CMatrix.get(i, j);
			final ElGamalMultiRecipientCiphertext modifiedCiphertext = elGamalGenerator.otherCiphertext(element);
			final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> modifiedCMatrix = GroupMatrices.set(CMatrix, i, j, modifiedCiphertext);

			MultiExponentiationStatement invalidStatment = new MultiExponentiationStatement(modifiedCMatrix, statement.getC(), statement.getcA());

			assertFalse(argumentService.verifyMultiExponentiationArgument(invalidStatment, argument));
		}

		@Test
		void testStatementWithModified_C_DoesNotVerify() {
			StatementWitnessPair pair = statementWitnessPairGenerator.genPair(n, m, l);
			MultiExponentiationStatement statement = pair.getStatement();
			MultiExponentiationWitness witness = pair.getWitness();
			MultiExponentiationArgument argument = argumentService.getMultiExponentiationArgument(statement, witness);

			final ElGamalMultiRecipientCiphertext modifiedCiphertext = elGamalGenerator.otherCiphertext(statement.getC());

			MultiExponentiationStatement invalidStatment =
					new MultiExponentiationStatement(statement.getCMatrix(), modifiedCiphertext, statement.getcA());

			assertFalse(argumentService.verifyMultiExponentiationArgument(invalidStatment, argument));
		}

		@Test
		void testStatementWithModified_cA_ElementDoesNotVerify() {
			StatementWitnessPair pair = statementWitnessPairGenerator.genPair(n, m, l);
			MultiExponentiationStatement statement = pair.getStatement();
			MultiExponentiationWitness witness = pair.getWitness();
			MultiExponentiationArgument argument = argumentService.getMultiExponentiationArgument(statement, witness);

			SameGroupVector<GqElement, GqGroup> cA = statement.getcA();
			int i = secureRandom.nextInt(cA.size());
			final GqElement modifiedElement = gqGroupGenerator.otherElement(cA.get(i));
			final SameGroupVector<GqElement, GqGroup> modifiedCA = GroupVectors.set(cA, i, modifiedElement);

			MultiExponentiationStatement invalidStatment =
					new MultiExponentiationStatement(statement.getCMatrix(), statement.getC(), modifiedCA);

			assertFalse(argumentService.verifyMultiExponentiationArgument(invalidStatment, argument));
		}

		@Test
		void testArgumentWithModified_cA0_ElementDoesNotVerify() {
			testInvalidArgument(MultiExponentiationArgument::getcA0, gqGroupGenerator::otherElement, MultiExponentiationArgument.Builder::withcA0);
		}

		@Test
		void testArgumentWithModified_cB_ElementDoesNotVerify() {
			UnaryOperator<SameGroupVector<GqElement, GqGroup>> modifycBVector = cB -> {
				int i = secureRandom.nextInt(cB.size());
				final GqElement element = cB.get(i);
				final GqElement modifiedElement = gqGroupGenerator.otherElement(element);
				return GroupVectors.set(cB, i, modifiedElement);
			};
			testInvalidArgument(MultiExponentiationArgument::getcBVector, modifycBVector, MultiExponentiationArgument.Builder::withcBVector);
		}

		@Test
		void testArgumentWithModified_E_ElementDoesNotVerify() {
			UnaryOperator<SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup>> modifyEVector = E -> {
				int i = secureRandom.nextInt(E.size());
				final ElGamalMultiRecipientCiphertext element = E.get(i);
				final ElGamalMultiRecipientCiphertext modifiedElement = elGamalGenerator.otherCiphertext(element);
				return GroupVectors.set(E, i, modifiedElement);
			};
			testInvalidArgument(MultiExponentiationArgument::getEVector, modifyEVector, MultiExponentiationArgument.Builder::withEVector);
		}

		@Test
		void testArgumentWithModified_a_ElementDoesNotVerify() {
			UnaryOperator<SameGroupVector<ZqElement, ZqGroup>> modifyaVector = aVector -> {
				int i = secureRandom.nextInt(aVector.size());
				final ZqElement element = aVector.get(i);
				ZqElement modifiedElement =  zqGroupGenerator.otherElement(element);
				return GroupVectors.set(aVector, i, modifiedElement);
			};
			testInvalidArgument(MultiExponentiationArgument::getaVector, modifyaVector, MultiExponentiationArgument.Builder::withaVector);
		}

		@Test
		void testArgumentWithModified_r_DoesNotVerify() {
			testInvalidArgument(MultiExponentiationArgument::getR, zqGroupGenerator::otherElement, MultiExponentiationArgument.Builder::withr);
		}

		@Test
		void testArgumentWithModified_b_ElementDoesNotVerify() {
			testInvalidArgument(MultiExponentiationArgument::getB, zqGroupGenerator::otherElement, MultiExponentiationArgument.Builder::withb);
		}

		@Test
		void testArgumentWithModified_s_DoesNotVerify() {
			testInvalidArgument(MultiExponentiationArgument::getS, zqGroupGenerator::otherElement, MultiExponentiationArgument.Builder::withs);
		}

		@Test
		void testArgumentWithModified_tau_DoesNotVerify() {
			testInvalidArgument(MultiExponentiationArgument::getTau, zqGroupGenerator::otherElement, MultiExponentiationArgument.Builder::withtau);
		}

		// <F> type of field to modify
		<F> void testInvalidArgument(
				Function<MultiExponentiationArgument, F> getField,
				UnaryOperator<F> modifyField,
				BiConsumer<MultiExponentiationArgument.Builder, F> setField) {

			StatementWitnessPair pair = statementWitnessPairGenerator.genPair(n, m, l);
			MultiExponentiationStatement statement = pair.getStatement();
			MultiExponentiationWitness witness = pair.getWitness();
			MultiExponentiationArgument argument = argumentService.getMultiExponentiationArgument(statement, witness);

			F field = getField.apply(argument);
			F newField = modifyField.apply(field);

			MultiExponentiationArgument.Builder builder = new MultiExponentiationArgument.Builder()
					.withb(argument.getB())
					.withaVector(argument.getaVector())
					.withr(argument.getR())
					.withs(argument.getS())
					.withtau(argument.getTau())
					.withcA0(argument.getcA0())
					.withcBVector(argument.getcBVector())
					.withEVector(argument.getEVector());
			setField.accept(builder, newField);

			MultiExponentiationArgument invalidArgument = builder.build();

			assertFalse(argumentService.verifyMultiExponentiationArgument(statement, invalidArgument));
		}
	}

	/**
	 * Mocks a HashService for test that returns the hash modulo q.
	 * @param q the modulus
	 * @return a HashService object with a mocked
	 */
	static private HashService getHashServiceMock(HashService delegate, BigInteger q) {
		HashService hashServiceMock = mock(HashService.class);
		when(hashServiceMock.recursiveHash(any())).thenAnswer(
				(Answer<byte[]>) invocationOnMock -> {
					Object[] args = invocationOnMock.getArguments();
					ImmutableList<Hashable> argsList = Arrays.stream(args).map(arg -> (Hashable) arg).collect(toImmutableList());
					HashableList hashables = HashableList.from(argsList);
					BigInteger hashModQ = byteArrayToInteger(delegate.recursiveHash(hashables)).mod(q);
					return integerToByteArray(hashModQ);
				}
		);
		return hashServiceMock;
	}
}