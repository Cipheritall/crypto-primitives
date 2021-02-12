/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.ConversionService.integerToByteArray;
import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;
import static ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationStatementWitnessPairGenerator.StatementWitnessPair;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.stubbing.Answer;

import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
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
	private static HashService hashService;
	private int n;
	private int m;
	private int l;
	private MultiExponentiationStatement randomStatement;
	private MultiExponentiationWitness randomWitness;

	@BeforeAll
	static void setUpAll() throws NoSuchAlgorithmException {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		publicKey = elGamalGenerator.genRandomPublicKey(KEY_ELEMENTS_NUMBER);

		commitmentKeyGenerator = new CommitmentKeyGenerator(gqGroup);
		commitmentKey = commitmentKeyGenerator.genCommitmentKey(KEY_ELEMENTS_NUMBER);
		randomService = new RandomService();

		hashService = new HashService(MessageDigest.getInstance("SHA-256"));
		// Mock the hashService in order to have a hash value of length smaller than q (preconditions on hashService)
		hashServiceMock = mock(HashService.class);
		when(hashServiceMock.recursiveHash(any())).thenAnswer(
				(Answer<byte[]>) invocationOnMock -> {
					Object[] args = invocationOnMock.getArguments();
					List<Object> argsList = Arrays.asList(args);
					BigInteger hashModQ = byteArrayToInteger(hashService.recursiveHash(argsList)).mod(gqGroup.getQ());
					return integerToByteArray(hashModQ);
				}
		);

		argumentService = new MultiExponentiationArgumentService(publicKey, commitmentKey, randomService, hashService);

		statementGenerator = new MultiExponentiationStatementGenerator(gqGroup);
		witnessGenerator = new MultiExponentiationWitnessGenerator(zqGroup);
		statementWitnessPairGenerator = new MultiExponentiationStatementWitnessPairGenerator(gqGroup, argumentService, commitmentKey);
	}

	@BeforeEach
	void setup() {
		n = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;
		m = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;
		l = secureRandom.nextInt(KEY_ELEMENTS_NUMBER - 1) + 1;

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
	void publicKeyAndCommitmentKeyFromSameGroup() {
		CommitmentKeyGenerator otherGenerator = new CommitmentKeyGenerator(otherGqGroup);
		CommitmentKey otherKey = otherGenerator.genCommitmentKey(KEY_ELEMENTS_NUMBER);
		assertThrowsIllegalArgumentExceptionWithMessage("The public key and commitment key must belong to the same group",
				() -> new MultiExponentiationArgumentService(publicKey, otherKey, randomService, hashService));
	}

	@Test
	void publicKeyAndCommitmentKeyOfDifferentSizeThrows() {
		CommitmentKey longerKey = commitmentKeyGenerator.genCommitmentKey(KEY_ELEMENTS_NUMBER + 1);
		assertThrowsIllegalArgumentExceptionWithMessage("The commitment key and public key must be of the same size.",
				() -> new MultiExponentiationArgumentService(publicKey, longerKey, randomService, hashService));
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

	////////// Utilities
	private static void assertThrowsIllegalArgumentExceptionWithMessage(String errorMsg, Executable executable) {
		Exception exception = assertThrows(IllegalArgumentException.class, executable);
		assertEquals(errorMsg, exception.getMessage());
	}

}