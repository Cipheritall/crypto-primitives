/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class ProductArgumentServiceTest {

	private static final int BOUND_FOR_RANDOM_ELEMENTS = 10;
	private static final RandomService randomService = new RandomService();
	private static final SecureRandom secureRandom = new SecureRandom();

	private int k;
	private GqGroup gqGroup;
	private GqGroupGenerator gqGroupGenerator;
	private HashService hashService;
	private ElGamalMultiRecipientPublicKey publicKey;
	private CommitmentKey commitmentKey;

	@BeforeEach
	void setup() throws NoSuchAlgorithmException {
		k = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS) + 1;
		gqGroup = GqGroupTestData.getGroup();
		gqGroupGenerator = new GqGroupGenerator(gqGroup);

		hashService = new HashService(MessageDigest.getInstance("SHA-256"));

		ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(gqGroup, k, randomService);
		publicKey = keyPair.getPublicKey();

		GqGroupGenerator generator = new GqGroupGenerator(gqGroup);
		GqElement h = generator.genNonIdentityNonGeneratorMember();
		List<GqElement> gList = Stream.generate(generator::genNonIdentityNonGeneratorMember).limit(k).collect(Collectors.toList());
		commitmentKey = new CommitmentKey(h, gList);
	}

	@Nested
	@DisplayName("Constructing a ProductArgumentService...")
	class ConstructorTest {

		@Test
		@DisplayName("with a null argument throws a NullPointerException")
		void constructProductArgumentWithNullArguments() {
			assertAll(
					() -> assertThrows(NullPointerException.class, () -> new ProductArgumentService(null, hashService, publicKey, commitmentKey)),
					() -> assertThrows(NullPointerException.class, () -> new ProductArgumentService(randomService, null, publicKey, commitmentKey)),
					() -> assertThrows(NullPointerException.class, () -> new ProductArgumentService(randomService, hashService, null, commitmentKey)),
					() -> assertThrows(NullPointerException.class, () -> new ProductArgumentService(randomService, hashService, publicKey, null))
			);
		}

		@Test
		@DisplayName("with public key from different group than commitment key throws an IllegalArgumentException")
		void constructProductArgumentWithPublicKeyGroupDifferentCommitmentKeyGroup() {
			GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			ElGamalMultiRecipientKeyPair keyPair = ElGamalMultiRecipientKeyPair.genKeyPair(differentGqGroup, k, randomService);
			publicKey = keyPair.getPublicKey();
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> new ProductArgumentService(randomService, hashService, publicKey, commitmentKey));
			assertEquals("The public key and the commitment key must belong to the same group.", exception.getMessage());
		}
	}

	@Nested
	@DisplayName("getProductArgument...")
	class GetProductArgumentTest {

		private int n;
		private int m;
		private ZqGroup zqGroup;
		private ZqGroupGenerator generator;
		private SameGroupVector<GqElement, GqGroup> commitmentsA;
		private ZqElement productB;
		private ProductStatement statement;
		private SameGroupMatrix<ZqElement, ZqGroup> matrixA;
		private SameGroupVector<ZqElement, ZqGroup> exponentsR;
		private ProductWitness witness;
		private ProductArgumentService productArgumentService;

		@BeforeEach
		void setup() {
			n = secureRandom.nextInt(k) + 1;
			m = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS - 1) + 2; // We need to have at least 2 columns
			zqGroup = ZqGroup.sameOrderAs(gqGroup);
			generator = new ZqGroupGenerator(zqGroup);
			ZqElement one = ZqElement.create(BigInteger.ONE, zqGroup);

			matrixA = generator.generateRandomZqElementMatrix(n, m);
			exponentsR = generator.generateRandomZqElementVector(m);
			witness = new ProductWitness(matrixA, exponentsR);
			commitmentsA = CommitmentService.getCommitmentMatrix(matrixA, exponentsR, commitmentKey);
			productB = matrixA.stream().reduce(one, ZqElement::multiply);
			statement = new ProductStatement(commitmentsA, productB);
			HashService mockHashService = mock(HashService.class);
			when(mockHashService.recursiveHash(any())).thenReturn(new byte[] { 0b10 });
			productArgumentService = new ProductArgumentService(randomService, mockHashService, publicKey, commitmentKey);
		}

		@Test
		@DisplayName("with valid parameters does not throw")
		void getProductArgumentWithValidParameters() {
			assertDoesNotThrow(() -> productArgumentService.getProductArgument(statement, witness));
		}

		@Test
		@DisplayName("with null arguments throws a NullPointerException")
		void getProductArgumentWithNullArguments() {
			assertThrows(NullPointerException.class, () -> productArgumentService.getProductArgument(null, witness));
			assertThrows(NullPointerException.class, () -> productArgumentService.getProductArgument(statement, null));
		}

		@Test
		@DisplayName("with statement and witness having incompatible sizes throws IllegalArgumentException")
		void getProductArgumentWithStatementAndWitnessDifferentSize() {
			commitmentsA = gqGroupGenerator.generateRandomGqElementList(m + 1);
			statement = new ProductStatement(commitmentsA, productB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> productArgumentService.getProductArgument(statement, witness));
			assertEquals("The commitments A and the exponents r must have the same size.", exception.getMessage());
		}

		@Test
		@DisplayName("with witness having a size incompatible with the commitment key throws an IllegalArgumentException")
		void getProductArgumentWithWitnessSizeIncompatibleWithCommitmentKeySize() {
			// Create a matrix with too many rows
			SameGroupMatrix<ZqElement, ZqGroup> otherMatrixA = generator.generateRandomZqElementMatrix(k + 1, m);
			witness = new ProductWitness(otherMatrixA, exponentsR);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> productArgumentService.getProductArgument(statement, witness));
			assertEquals("The matrix' number of rows cannot be greater than the commitment key size.", exception.getMessage());
		}

		@Test
		@DisplayName("with statement and witness having incompatible groups throws IllegalArgumentException")
		void getProductArgumentWithStatementAndWitnessDifferentGroup() {
			GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			ZqGroup differentZqGroup = ZqGroup.sameOrderAs(differentGqGroup);
			commitmentsA = new GqGroupGenerator(differentGqGroup).generateRandomGqElementList(m);
			productB = new ZqGroupGenerator(differentZqGroup).genZqElementMember();
			statement = new ProductStatement(commitmentsA, productB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> productArgumentService.getProductArgument(statement, witness));
			assertEquals("The product b and the matrix A must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with commitments and commitment key from different group throws IllegalArgumentException")
		void getProductArgumentWithCommitmentsAndCommitmentKeyFromDifferentGroups() {
			GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			ZqGroup differentZqGroup = ZqGroup.sameOrderAs(differentGqGroup);
			ZqGroupGenerator differentZqGroupGenerator = new ZqGroupGenerator(differentZqGroup);
			ZqElement one = ZqElement.create(BigInteger.ONE, differentZqGroup);

			matrixA = differentZqGroupGenerator.generateRandomZqElementMatrix(n, m);
			exponentsR = differentZqGroupGenerator.generateRandomZqElementVector(m);
			witness = new ProductWitness(matrixA, exponentsR);

			GqGroupGenerator differentGqGroupGenerator = new GqGroupGenerator(differentGqGroup);
			GqElement h = differentGqGroupGenerator.genNonIdentityNonGeneratorMember();
			List<GqElement> gList = Stream.generate(differentGqGroupGenerator::genNonIdentityNonGeneratorMember).limit(k)
					.collect(Collectors.toList());
			CommitmentKey differentCommitmentKey = new CommitmentKey(h, gList);
			commitmentsA = CommitmentService.getCommitmentMatrix(matrixA, exponentsR, differentCommitmentKey);
			productB = matrixA.stream().reduce(one, ZqElement::multiply);
			statement = new ProductStatement(commitmentsA, productB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> productArgumentService.getProductArgument(statement, witness));
			assertEquals("The commitment key and the commitments must have the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with a matrix with too few columns throws an IllegalArgumentException")
		void getProductArgumentWithTooSmallMatrix() {
			matrixA = generator.generateRandomZqElementMatrix(n, 1);
			exponentsR = generator.generateRandomZqElementVector(1);
			witness = new ProductWitness(matrixA, exponentsR);
			commitmentsA = CommitmentService.getCommitmentMatrix(matrixA, exponentsR, commitmentKey);
			ZqElement one = ZqElement.create(BigInteger.ONE, zqGroup);
			productB = matrixA.stream().reduce(one, ZqElement::multiply);
			statement = new ProductStatement(commitmentsA, productB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> productArgumentService.getProductArgument(statement, witness));
			assertEquals("The matrix A must have at least 2 columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with incompatible commitment and matrix throws an IllegalArgumentException")
		void getProductArgumentWithBadCommitment() {
			List<GqElement> commitmentList = commitmentsA.stream().collect(Collectors.toCollection(ArrayList::new));
			GqElement g = commitmentsA.getGroup().getGenerator();
			GqElement first = commitmentList.get(0);
			first = first.multiply(g);
			commitmentList.set(0, first);
			commitmentsA = new SameGroupVector<>(commitmentList);
			statement = new ProductStatement(commitmentsA, productB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> productArgumentService.getProductArgument(statement, witness));
			assertEquals("The commitment to matrix A with exponents r using the given commitment key must yield the commitments cA.",
					exception.getMessage());
		}

		@Test
		@DisplayName("with a product that does not correspond to the matrix product throws a IllegalArgumentException")
		void getProductArgumentWithBadProduct() {
			ZqElement one = ZqElement.create(BigInteger.ONE, ZqGroup.sameOrderAs(gqGroup));
			productB = productB.add(one);
			statement = new ProductStatement(commitmentsA, productB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> productArgumentService.getProductArgument(statement, witness));
			assertEquals("The product of all elements in matrix A must be equal to b.",
					exception.getMessage());
		}

		@Test
		@DisplayName("with specific values returns the expected result")
		void getProductArgumentWithSpecificValues() {
			// Create groups
			BigInteger p = BigInteger.valueOf(11);
			BigInteger q = BigInteger.valueOf(5);
			BigInteger g = BigInteger.valueOf(3);
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
			ElGamalMultiRecipientPublicKey productPublicKey = keyPair.getPublicKey();
			CommitmentKey productCommitmentKey = new CommitmentKey(gqNine, Arrays.asList(gqFour, gqNine));
			RandomService productRandomService = mock(RandomService.class);
			HashService productHashService = mock(HashService.class);

			BigInteger zero = BigInteger.ZERO;
			BigInteger one = BigInteger.ONE;
			BigInteger two = BigInteger.valueOf(2);
			BigInteger three = BigInteger.valueOf(3);
			BigInteger four = BigInteger.valueOf(4);

			when(productRandomService.genRandomInteger(any()))
					.thenReturn(four, // s
							three, // s_1
							one, three, // a_0
							two, one, // b_m
							four, // r_0
							zero, // s_m
							zero, one, three, four, two, one, two, // t
							four, one, zero, // d_0, d_1, r_d
							one, two // s_0, s_x
					);
			when(productHashService.recursiveHash(any()))
					.thenReturn(new byte[] { 0b10 }, new byte[] { 0b11 }, new byte[] { 0b01 }, new byte[] { 0b10 });
			ProductArgumentService specificProductArgumentService = new ProductArgumentService(productRandomService, productHashService,
					productPublicKey, productCommitmentKey);

			// Create A and r
			List<List<ZqElement>> matrixColumns = new ArrayList<>(m);
			matrixColumns.add(0, Arrays.asList(zqOne, zqThree));
			matrixColumns.add(1, Arrays.asList(zqTwo, zqFour));
			matrixColumns.add(2, Arrays.asList(zqZero, zqOne));
			SameGroupMatrix<ZqElement, ZqGroup> matrix = SameGroupMatrix.fromColumns(matrixColumns);
			SameGroupVector<ZqElement, ZqGroup> exponents = new SameGroupVector<>(Arrays.asList(zqOne, zqTwo, zqFour));

			ProductWitness productWitness = new ProductWitness(matrix, exponents);

			// Calculate c_A and b
			SameGroupVector<GqElement, GqGroup> commitmentsA = CommitmentService.getCommitmentMatrix(matrix, exponents, productCommitmentKey);
			ZqElement product = matrix.stream().reduce(zqOne, ZqElement::multiply);

			ProductStatement productStatement = new ProductStatement(commitmentsA, product);

			// Create the expected zeroArgument
			ZeroArgument expectedZeroArgument = new ZeroArgument.ZeroArgumentBuilder().withCA0(gqFive)
					.withCBm(gqOne)
					.withCd(SameGroupVector.of(gqNine, gqFive, gqThree, gqThree, gqOne, gqFour, gqFour))
					.withAPrime(SameGroupVector.of(zqTwo, zqTwo))
					.withBPrime(SameGroupVector.of(zqOne, zqTwo))
					.withRPrime(zqZero)
					.withSPrime(zqOne)
					.withTPrime(zqOne)
					.build();

			// Create the Hadamard product argument's expected c_(B_0), c_(B_1), c_(B_2)
			SameGroupVector<GqElement, GqGroup> commitmentsB = SameGroupVector.of(gqNine, gqFive, gqNine);
			// Create the expected HadamardArgument
			HadamardArgument expectedHadamardArgument = new HadamardArgument(commitmentsB, expectedZeroArgument);

			// Create the expected SingleValueProductArgument
			SingleValueProductArgument expectedSingleValueProductArgument = new SingleValueProductArgument.SingleValueProductArgumentBuilder()
					.withCLowerD(gqFive)
					.withCLowerDelta(gqThree)
					.withCUpperDelta(gqThree)
					.withATilde(SameGroupVector.of(zqFour, zqZero))
					.withBTilde(SameGroupVector.of(zqFour, zqOne))
					.withRTilde(zqThree)
					.withSTilde(zqZero)
					.build();

			// Create the expected ProductArgument
			ProductArgument expectedProductArgument = new ProductArgument(gqNine, expectedHadamardArgument, expectedSingleValueProductArgument);

			assertEquals(expectedProductArgument, specificProductArgumentService.getProductArgument(productStatement, productWitness));
		}
	}
}