/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
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

class HadamardArgumentServiceTest {

	private static final int MATRIX_BOUNDS = 10;
	private static final SecureRandom secureRandom = new SecureRandom();
	private static final RandomService randomService = new RandomService();

	private static HashService hashService;
	private static int n;
	private static int m;

	private static GqGroup gqGroup;
	private static ElGamalMultiRecipientPublicKey publicKey;
	private static CommitmentKey commitmentKey;
	private static HadamardArgumentService hadamardArgumentService;

	private HadamardStatement statement;
	private HadamardWitness witness;

	@BeforeAll
	static void setupAll() {
		n = secureRandom.nextInt(MATRIX_BOUNDS) + 1;
		m = secureRandom.nextInt(MATRIX_BOUNDS - 1) + 2; // The Hadamard argument only works with 2 or more columns
		gqGroup = GroupTestData.getGqGroup();
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, n, randomService);
		publicKey = keyPair.getPublicKey();
		GqGroupGenerator generator = new GqGroupGenerator(gqGroup);
		commitmentKey = new CommitmentKey(generator.genNonIdentityNonGeneratorMember(),
				IntStream.range(0, n).mapToObj(i -> generator.genNonIdentityNonGeneratorMember()).collect(Collectors.toList()));
		hashService = mock(HashService.class);
		when(hashService.recursiveHash(any()))
				.thenReturn(new byte[] { 0b10 });
		hadamardArgumentService = new HadamardArgumentService(randomService, hashService, publicKey, commitmentKey);
	}

	@Test
	@DisplayName("Instantiating a Hadamard argument provider with valid arguments does not throw")
	void constructHadamardArgumentService() {
		assertDoesNotThrow(() -> new HadamardArgumentService(randomService, hashService, publicKey, commitmentKey));
	}

	@Test
	@DisplayName("Instantiating a Hadamard argument provider with null arguments throws a NullPointerException")
	void constructHadamardArgumentServiceWithNullArguments() {
		assertAll(
				() -> assertThrows(NullPointerException.class, () -> new HadamardArgumentService(null, hashService, publicKey, commitmentKey)),
				() -> assertThrows(NullPointerException.class, () -> new HadamardArgumentService(randomService, null, publicKey, commitmentKey)),
				() -> assertThrows(NullPointerException.class, () -> new HadamardArgumentService(randomService, hashService, null, commitmentKey)),
				() -> assertThrows(NullPointerException.class, () -> new HadamardArgumentService(randomService, hashService, publicKey, null))
		);
	}

	@Test
	@DisplayName("Instantiating a Hadamard argument provider with a public key and a commitment key of different sizes throws")
	void constructHadamardArgumentServiceWithKeysDifferentSize() {
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, n + 1, randomService);
		ElGamalMultiRecipientPublicKey otherPublicKey = keyPair.getPublicKey();
		Exception exception = assertThrows(IllegalArgumentException.class,
				() -> new HadamardArgumentService(randomService, hashService, otherPublicKey, commitmentKey));
		assertEquals("The public key and the commitment key must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("Instantiating a Hadamard argument provider with a public key and a commitment key from a different group throws")
	void constructHadamardArgumentServiceWithKeysDifferentGroup() {
		GqGroup differentGqGroup = GroupTestData.getDifferentGqGroup(gqGroup);
		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(differentGqGroup, n, randomService);
		ElGamalMultiRecipientPublicKey otherPublicKey = keyPair.getPublicKey();
		Exception exception = assertThrows(IllegalArgumentException.class,
				() -> new HadamardArgumentService(randomService, hashService, otherPublicKey, commitmentKey));
		assertEquals("The public key and the commitment key must belong to the same group.", exception.getMessage());
	}

	@Nested
	@DisplayName("Calculating a Hadamard argument...")
	class GetHadamardArgumentTest {

		private ZqGroup zqGroup;
		private ZqGroupGenerator zqGenerator;

		private SameGroupVector<GqElement, GqGroup> commitmentsA;
		private GqElement commitmentB;
		private SameGroupMatrix<ZqElement, ZqGroup> matrix;
		private SameGroupVector<ZqElement, ZqGroup> vector;
		private SameGroupVector<ZqElement, ZqGroup> exponents;
		private ZqElement randomness;

		@BeforeEach
		void setup() {
			zqGroup = ZqGroup.sameOrderAs(gqGroup);
			ZqElement one = ZqElement.create(BigInteger.ONE, zqGroup);

			// Generate the Hadamard witness
			zqGenerator = new ZqGroupGenerator(zqGroup);
			matrix = zqGenerator.genRandomZqElementMatrix(n, m);
			vector = IntStream.range(0, n).mapToObj(i -> matrix.getRow(i).stream().reduce(one, ZqElement::multiply))
					.collect(toSameGroupVector());
			exponents = zqGenerator.genRandomZqElementVector(m);
			randomness = zqGenerator.genRandomZqElementMember();
			witness = new HadamardWitness(matrix, vector, exponents, randomness);

			// Generate the Hadamard statement
			commitmentsA = CommitmentService.getCommitmentMatrix(matrix, exponents, commitmentKey);
			commitmentB = CommitmentService.getCommitment(vector, randomness, commitmentKey);
			statement = new HadamardStatement(commitmentsA, commitmentB);
		}

		@Test
		@DisplayName("with valid arguments does not throw")
		void testGetHadamardArgument() {
			assertDoesNotThrow(() -> hadamardArgumentService.getHadamardArgument(statement, witness));
		}

		@Test
		@DisplayName("with null arguments throws a NullPointerException")
		void getHadamardArgumentWithNullArguments() {
			assertThrows(NullPointerException.class, () -> hadamardArgumentService.getHadamardArgument(null, witness));
			assertThrows(NullPointerException.class, () -> hadamardArgumentService.getHadamardArgument(statement, null));
		}

		@Test
		@DisplayName("with too few columns throws an IllegalArgumentException")
		void getHadamardArgumentWithTooFewColumns() {

			// Generate the Hadamard witness
			SameGroupMatrix<ZqElement, ZqGroup> matrix = zqGenerator.genRandomZqElementMatrix(n, 1);
			SameGroupVector<ZqElement, ZqGroup> vector = zqGenerator.genRandomZqElementVector(n);
			SameGroupVector<ZqElement, ZqGroup> exponents = zqGenerator.genRandomZqElementVector(1);
			ZqElement randomness = zqGenerator.genRandomZqElementMember();
			witness = new HadamardWitness(matrix, vector, exponents, randomness);

			// Generate the Hadamard statement
			SameGroupVector<GqElement, GqGroup> commitmentsA = CommitmentService.getCommitmentMatrix(matrix, exponents, commitmentKey);
			GqElement commitmentB = CommitmentService.getCommitment(vector, randomness, commitmentKey);
			statement = new HadamardStatement(commitmentsA, commitmentB);

			Exception exception = assertThrows(IllegalArgumentException.class, () -> hadamardArgumentService.getHadamardArgument(statement, witness));
			assertEquals("The matrix must have at least 2 columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with too long commitments for A throws an IllegalArgumentException")
		void getHadamardArgumentWithTooLongCommitmentsA() {
			List<GqElement> commitmentsAList = commitmentsA.stream().collect(Collectors.toList());
			commitmentsAList.add(gqGroup.getIdentity());
			commitmentsA = new SameGroupVector<>(commitmentsAList);
			statement = new HadamardStatement(commitmentsA, commitmentB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> hadamardArgumentService.getHadamardArgument(statement, witness));
			assertEquals("The commitments for A must have as many elements as matrix A has rows.", exception.getMessage());
		}

		@Test
		@DisplayName("with too short commitments for A throws an IllegalArgumentException")
		void getHadamardArgumentWithTooShortCommitmentsA() {
			List<GqElement> commitmentsAList = commitmentsA.stream().collect(Collectors.toList());
			commitmentsAList.remove(0);
			commitmentsA = new SameGroupVector<>(commitmentsAList);
			statement = new HadamardStatement(commitmentsA, commitmentB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> hadamardArgumentService.getHadamardArgument(statement, witness));
			assertEquals("The commitments for A must have as many elements as matrix A has rows.", exception.getMessage());
		}

		@Test
		@DisplayName("with the statement having a different group than the witness throws an IllegalArgumentException")
		void getHadamardArgumentWithCommitmentsFromDifferentGroup() {
			GqGroup differentGqGroup = GroupTestData.getDifferentGqGroup(gqGroup);
			GqGroupGenerator generator = new GqGroupGenerator(differentGqGroup);
			commitmentsA = generator.genRandomGqElementVector(m);
			commitmentB = generator.genMember();
			statement = new HadamardStatement(commitmentsA, commitmentB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> hadamardArgumentService.getHadamardArgument(statement, witness));
			assertEquals("The matrix A and its commitments must have the same group order q.", exception.getMessage());
		}

		@Test
		@DisplayName("with too short public key and commitment key throws an IllegalArgumentException")
		void getHadamardArgumentWithTooShortKeys() {
			zqGroup = ZqGroup.sameOrderAs(gqGroup);
			ZqElement one = ZqElement.create(BigInteger.ONE, zqGroup);

			// Generate the Hadamard witness
			zqGenerator = new ZqGroupGenerator(zqGroup);
			matrix = zqGenerator.genRandomZqElementMatrix(n + 1, m);
			vector = IntStream.range(0, n + 1).mapToObj(i -> matrix.getRow(i).stream().reduce(one, ZqElement::multiply))
					.collect(toSameGroupVector());
			exponents = zqGenerator.genRandomZqElementVector(m);
			randomness = zqGenerator.genRandomZqElementMember();
			witness = new HadamardWitness(matrix, vector, exponents, randomness);

			// Generate the Hadamard statement
			GqGroupGenerator gqGenerator = new GqGroupGenerator(gqGroup);
			commitmentsA = gqGenerator.genRandomGqElementVector(m);
			commitmentB = gqGenerator.genMember();
			statement = new HadamardStatement(commitmentsA, commitmentB);

			Exception exception = assertThrows(IllegalArgumentException.class, () -> hadamardArgumentService.getHadamardArgument(statement, witness));
			assertEquals("The number of rows in the matrix must be smaller than the commitment key size.", exception.getMessage());
		}

		@Test
		@DisplayName("with wrong commitments for b throws an IllegalArgumentException")
		void getHadamardArgumentWithWrongCommitmentsA() {
			List<GqElement> commitmentsAList = commitmentsA.stream().collect(Collectors.toCollection(ArrayList::new));
			GqElement first = commitmentsAList.get(0);
			first = first.multiply(gqGroup.getGenerator());
			commitmentsAList.set(0, first);
			commitmentsA = new SameGroupVector<>(commitmentsAList);
			statement = new HadamardStatement(commitmentsA, commitmentB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> hadamardArgumentService.getHadamardArgument(statement, witness));
			assertEquals("The commitments A must correspond to the commitment to matrix A with exponents r and the given commitment key.",
					exception.getMessage());
		}

		@Test
		@DisplayName("with a wrong commitment for b throws an IllegalArgumentException")
		void getHadamardArgumentWithWrongCommitmentB() {
			commitmentB = commitmentB.multiply(gqGroup.getGenerator());
			statement = new HadamardStatement(commitmentsA, commitmentB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> hadamardArgumentService.getHadamardArgument(statement, witness));
			assertEquals("The commitment b must correspond to the commitment to vector b with exponent s and the given commitment key.",
					exception.getMessage());
		}

		@Test
		@DisplayName("with a wrong product b throws an IllegalArgumentException")
		void getHadamardArgumentWithWrongProduct() {
			List<ZqElement> vectorElements = vector.stream().collect(Collectors.toCollection(ArrayList::new));
			ZqElement first = vectorElements.get(0);
			first = first.add(ZqElement.create(BigInteger.ONE, zqGroup));
			vectorElements.set(0, first);
			vector = new SameGroupVector<>(vectorElements);
			witness = new HadamardWitness(matrix, vector, exponents, randomness);
			commitmentB = CommitmentService.getCommitment(vector, randomness, commitmentKey);
			statement = new HadamardStatement(commitmentsA, commitmentB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> hadamardArgumentService.getHadamardArgument(statement, witness));
			assertEquals("The vector b must correspond to the product of the column vectors of the matrix A.",
					exception.getMessage());
		}

		@Test
		@DisplayName("with specific values returns the expected result")
		void getHadamardArgumentWithSpecificValues() {
			// Create groups
			BigInteger p = BigInteger.valueOf(11);
			BigInteger q = BigInteger.valueOf(5L);
			BigInteger g = BigInteger.valueOf(3L);
			GqGroup gqGroup = new GqGroup(p, q, g);
			ZqGroup zqGroup = new ZqGroup(q);

			// Instantiate group elements
			GqElement gqOne = GqElement.create(BigInteger.ONE, gqGroup);
			GqElement gqThree = GqElement.create(BigInteger.valueOf(3), gqGroup);
			GqElement gqFour = GqElement.create(BigInteger.valueOf(4), gqGroup);
			GqElement gqFive = GqElement.create(BigInteger.valueOf(5), gqGroup);
			GqElement gqNine = GqElement.create(BigInteger.valueOf(9), gqGroup);

			ZqElement zqZero = ZqElement.create(BigInteger.ZERO, zqGroup);
			ZqElement zqOne = ZqElement.create(BigInteger.ONE, zqGroup);
			ZqElement zqTwo = ZqElement.create(BigInteger.valueOf(2), zqGroup);
			ZqElement zqThree = ZqElement.create(BigInteger.valueOf(3), zqGroup);
			ZqElement zqFour = ZqElement.create(BigInteger.valueOf(4), zqGroup);

			// Create HadamardArgumentService
			int n = 2;
			int m = 3;
			ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, n, randomService);
			ElGamalMultiRecipientPublicKey hadamardPublicKey = keyPair.getPublicKey();
			CommitmentKey hadamardCommitmentKey = new CommitmentKey(gqNine, Arrays.asList(gqFour, gqNine));
			RandomService hadamardRandomService = mock(RandomService.class);
			HashService hadamardHashService = mock(HashService.class);

			BigInteger zero = BigInteger.ZERO;
			BigInteger one = BigInteger.ONE;
			BigInteger two = BigInteger.valueOf(2);
			BigInteger three = BigInteger.valueOf(3);
			BigInteger four = BigInteger.valueOf(4);

			when(hadamardRandomService.genRandomInteger(any()))
					.thenReturn(three, // s_1
							one, three, // a_0
							two, one, // b_m
							four, // r_0
							zero, // s_m
							zero, one, three, four, two, one, two // t
					);
			when(hadamardHashService.recursiveHash(any()))
					.thenReturn(new byte[] { 0b10 });
			HadamardArgumentService specificHadamardArgumentService = new HadamardArgumentService(hadamardRandomService, hadamardHashService, hadamardPublicKey, hadamardCommitmentKey);

			// Create A
			List<List<ZqElement>> matrixColumns = new ArrayList<>(m);
			matrixColumns.add(0, Arrays.asList(zqFour, zqZero));
			matrixColumns.add(1, Arrays.asList(zqTwo, zqTwo));
			matrixColumns.add(2, Arrays.asList(zqZero, zqFour));
			SameGroupMatrix<ZqElement, ZqGroup> matrix = SameGroupMatrix.fromColumns(matrixColumns);

			// Create b
			SameGroupVector<ZqElement, ZqGroup> vector = new SameGroupVector<>(Arrays.asList(zqZero, zqZero));

			// Create r
			SameGroupVector<ZqElement, ZqGroup> exponents = new SameGroupVector<>(Arrays.asList(zqThree, zqThree, zqFour));

			// Create s
			ZqElement randomness = zqTwo;
			HadamardWitness hadamardWitness = new HadamardWitness(matrix, vector, exponents, randomness);

			// Calculate c_A and c_b
			SameGroupVector<GqElement, GqGroup> commitmentsA = CommitmentService.getCommitmentMatrix(matrix, exponents, hadamardCommitmentKey);
			GqElement commitmentB = CommitmentService.getCommitment(vector, randomness, hadamardCommitmentKey);
			HadamardStatement hadamardStatement = new HadamardStatement(commitmentsA, commitmentB);

			// Create the expected c_B
			SameGroupVector<GqElement, GqGroup> cB = SameGroupVector.of(gqNine, gqFive, gqFour);

			// Create the expected ZeroArgument
			ZeroArgument zeroArgument = new ZeroArgument.Builder()
					.withCA0(gqFive)
					.withCBm(gqOne)
					.withCd(new SameGroupVector<>(Arrays.asList(gqFour, gqFour, gqNine, gqNine, gqOne, gqThree, gqOne)))
					.withAPrime(new SameGroupVector<>(Arrays.asList(zqTwo, zqZero)))
					.withBPrime(new SameGroupVector<>(Arrays.asList(zqOne, zqOne)))
					.withRPrime(zqOne)
					.withSPrime(zqFour)
					.withTPrime(zqOne)
					.build();

			// Create the expected HadamardArgument
			HadamardArgument expected = new HadamardArgument(cB, zeroArgument);

			assertEquals(expected, specificHadamardArgumentService.getHadamardArgument(hadamardStatement, hadamardWitness));
		}
	}

	@Nested
	@DisplayName("Verifying a Hadamard argument...")
	class VerifyHadamardArgumentTest {

		private ZqGroup zqGroup;

		private HadamardArgument argument;

		@BeforeEach
		void setup() {
			zqGroup = ZqGroup.sameOrderAs(gqGroup);
			ZqElement one = ZqElement.create(BigInteger.ONE, zqGroup);

			// Generate the Hadamard witness
			ZqGroupGenerator zqGenerator = new ZqGroupGenerator(zqGroup);
			SameGroupMatrix<ZqElement, ZqGroup> matrix = zqGenerator.genRandomZqElementMatrix(n, m);
			SameGroupVector<ZqElement, ZqGroup> vector = IntStream.range(0, n)
					.mapToObj(i -> matrix.getRow(i).stream().reduce(one, ZqElement::multiply))
					.collect(toSameGroupVector());
			SameGroupVector<ZqElement, ZqGroup> exponents = zqGenerator.genRandomZqElementVector(m);
			ZqElement randomness = zqGenerator.genRandomZqElementMember();
			HadamardWitness witness = new HadamardWitness(matrix, vector, exponents, randomness);

			// Generate the Hadamard statement
			SameGroupVector<GqElement, GqGroup> commitmentsA = CommitmentService.getCommitmentMatrix(matrix, exponents, commitmentKey);
			GqElement commitmentB = CommitmentService.getCommitment(vector, randomness, commitmentKey);
			statement = new HadamardStatement(commitmentsA, commitmentB);

			argument = hadamardArgumentService.getHadamardArgument(statement, witness);
		}

		@Test
		@DisplayName("with null arguments throws a NullPointerException")
		void verifyHadamardArgumentWithNullArguments() {
			assertThrows(NullPointerException.class, () -> hadamardArgumentService.verifyHadamardArgument(null, argument));
			assertThrows(NullPointerException.class, () -> hadamardArgumentService.verifyHadamardArgument(statement, null));
		}

		@Test
		@DisplayName("with correct input returns true")
		void verifyHadamardArgumentWithCorrectInput() {
			assertTrue(hadamardArgumentService.verifyHadamardArgument(statement, argument));
		}

		@Test
		@DisplayName("with bad values for cUpperB returns false")
		void verifyHadamardArgumentWithBadcUpperB() {
			SameGroupVector<GqElement, GqGroup> cUpperB = argument.getCommitmentsB();

			GqElement badcUpperB0 = cUpperB.get(0).multiply(gqGroup.getGenerator());
			SameGroupVector<GqElement, GqGroup> badcUpperB = cUpperB.stream().skip(1).collect(toSameGroupVector()).prepend(badcUpperB0);
			HadamardArgument badArgument = new HadamardArgument(badcUpperB, argument.getZeroArgument());

			assertFalse(hadamardArgumentService.verifyHadamardArgument(statement, badArgument));

			int m = cUpperB.size();
			GqElement badcUpperBmMinusOne = cUpperB.get(m - 1).multiply(gqGroup.getGenerator());
			badcUpperB = new SameGroupVector<>(cUpperB.stream().collect(Collectors.toList()).subList(0, m - 1)).append(badcUpperBmMinusOne);
			badArgument = new HadamardArgument(badcUpperB, argument.getZeroArgument());

			assertFalse(hadamardArgumentService.verifyHadamardArgument(statement, badArgument));
		}

		@Test
		@DisplayName("with bad values for ZeroArgument returns false")
		void verifyHadamardArgumentWithBadZeroArgument() {
			ZeroArgument zeroArgument = argument.getZeroArgument();
			GqElement badcA0 = zeroArgument.getCA0().multiply(gqGroup.getGenerator());
			ZeroArgument badZeroArgument = new ZeroArgument.Builder()
					.withCA0(badcA0)
					.withCBm(zeroArgument.getCBm())
					.withCd(zeroArgument.getCd())
					.withAPrime(zeroArgument.getAPrime())
					.withBPrime(zeroArgument.getBPrime())
					.withRPrime(zeroArgument.getRPrime())
					.withSPrime(zeroArgument.getSPrime())
					.withTPrime(zeroArgument.getTPrime())
					.build();
			HadamardArgument badArgument = new HadamardArgument(argument.getCommitmentsB(), badZeroArgument);
			assertFalse(hadamardArgumentService.verifyHadamardArgument(statement, badArgument));
		}
	}

	@Nested
	@DisplayName("Calculating the Hadamard product...")
	class GetHadamardProductTest {

		private SameGroupMatrix<ZqElement, ZqGroup> matrix;

		@BeforeEach
		void setup() {
			ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);
			ZqGroupGenerator zqGenerator = new ZqGroupGenerator(zqGroup);
			matrix = zqGenerator.genRandomZqElementMatrix(n, m);
		}

		@Test
		@DisplayName("with a null matrix throws a NullPointerException")
		void getHadamardProductWithNullMatrix() {
			assertThrows(NullPointerException.class, () -> hadamardArgumentService.getHadamardProduct(null, 0));
		}

		@Test
		@DisplayName("with wrong indexes throws an IllegalArgumentException")
		void getHadamardProductWithIndexOutOfBounds() {
			Exception exception = assertThrows(IllegalArgumentException.class, () -> hadamardArgumentService.getHadamardProduct(matrix, -1));
			assertEquals("The column index must be greater than or equal to 0.", exception.getMessage());
			exception = assertThrows(IllegalArgumentException.class, () -> hadamardArgumentService.getHadamardProduct(matrix, m));
			assertEquals("The column index must be smaller than the number of rows in the matrix.", exception.getMessage());
		}

		@Test
		@DisplayName("with valid indexes does not throw")
		void getHadamardProductWithValidIndexes() {
			assertDoesNotThrow(() -> hadamardArgumentService.getHadamardProduct(matrix, 0));
			assertDoesNotThrow(() -> hadamardArgumentService.getHadamardProduct(matrix, m - 1));
		}

		@Test
		@DisplayName("with specific values returns the expected result")
		void getHadamardProductWithSpecificValues() {
			ZqGroup group = new ZqGroup(BigInteger.valueOf(11));
			List<List<ZqElement>> columns = new ArrayList<>(3);
			// Column1 = [1, 2]
			List<ZqElement> column1 = new ArrayList<>(2);
			column1.add(ZqElement.create(BigInteger.ONE, group));
			column1.add(ZqElement.create(BigInteger.valueOf(2), group));
			columns.add(column1);
			// Column2 = [3, 4]
			List<ZqElement> column2 = new ArrayList<>(2);
			column2.add(ZqElement.create(BigInteger.valueOf(3), group));
			column2.add(ZqElement.create(BigInteger.valueOf(4), group));
			columns.add(column2);
			// Column3 = [5, 6]
			List<ZqElement> column3 = new ArrayList<>(2);
			column3.add(ZqElement.create(BigInteger.valueOf(5), group));
			column3.add(ZqElement.create(BigInteger.valueOf(6), group));
			columns.add(column3);
			SameGroupMatrix<ZqElement, ZqGroup> columnMatrix = SameGroupMatrix.fromColumns(columns);

			// getHadamardProduct with j = 0 yields the first column vector
			assertEquals(new SameGroupVector<>(column1), hadamardArgumentService.getHadamardProduct(columnMatrix, 0));

			// getHadamardProduct with j = 1 yields the vector [3, 8]
			List<ZqElement> result2 = new ArrayList<>(2);
			result2.add(ZqElement.create(BigInteger.valueOf(3), group));
			result2.add(ZqElement.create(BigInteger.valueOf(8), group));
			assertEquals(new SameGroupVector<>(result2), hadamardArgumentService.getHadamardProduct(columnMatrix, 1));

			// getHadamardProduct with j = 2 yields the vector [3, 8]
			List<ZqElement> result3 = new ArrayList<>(2);
			result3.add(ZqElement.create(BigInteger.valueOf(4), group));
			result3.add(ZqElement.create(BigInteger.valueOf(4), group));
			assertEquals(new SameGroupVector<>(result3), hadamardArgumentService.getHadamardProduct(columnMatrix, 2));
		}
	}
}