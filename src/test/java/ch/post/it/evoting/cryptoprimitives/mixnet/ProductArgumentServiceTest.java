/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.ConversionService.integerToByteArray;
import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;
import static ch.post.it.evoting.cryptoprimitives.mixnet.ProductGenerator.genProductWitness;
import static ch.post.it.evoting.cryptoprimitives.mixnet.ProductGenerator.getProductStatement;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.Answer;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.Hashable;
import ch.post.it.evoting.cryptoprimitives.HashableList;
import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

class ProductArgumentServiceTest extends TestGroupSetup {

	private static final int BOUND_FOR_RANDOM_ELEMENTS = 10;
	private static final RandomService randomService = new RandomService();
	private static final SecureRandom secureRandom = new SecureRandom();

	private int k;
	private HashService hashService;
	private ElGamalMultiRecipientPublicKey publicKey;
	private CommitmentKey commitmentKey;

	@BeforeEach
	void setup() throws NoSuchAlgorithmException {
		k = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS - 2) + 2;

		hashService = new HashService(MessageDigest.getInstance("SHA-256"));
		publicKey = new ElGamalGenerator(gqGroup).genRandomPublicKey(k);

		commitmentKey = new CommitmentKeyGenerator(gqGroup).genCommitmentKey(k);
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
			ElGamalMultiRecipientPublicKey otherPublicKey = new ElGamalGenerator(otherGqGroup).genRandomPublicKey(k);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> new ProductArgumentService(randomService, hashService, otherPublicKey, commitmentKey));
			assertEquals("The public key and the commitment key must belong to the same group.", exception.getMessage());
		}
	}

	@Nested
	@DisplayName("getProductArgument...")
	class GetProductArgumentTest {

		private int n;
		private int m;
		private SameGroupVector<GqElement, GqGroup> commitmentsA;
		private ZqElement productB;
		private ProductStatement statement;
		private SameGroupMatrix<ZqElement, ZqGroup> matrixA;
		private SameGroupVector<ZqElement, ZqGroup> exponentsR;
		private ProductWitness witness;
		private HashService mockHashService;
		private ProductArgumentService productArgumentService;

		@BeforeEach
		void setup() {
			n = secureRandom.nextInt(k - 1) + 2;
			m = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS) + 1;
			ZqElement one = ZqElement.create(BigInteger.ONE, zqGroup);

			witness = genProductWitness(n, m, zqGroupGenerator);
			matrixA = witness.getMatrix();
			exponentsR = witness.getExponents();
			statement = getProductStatement(witness, commitmentKey);
			commitmentsA = statement.getCommitments();
			productB = statement.getProduct();

			mockHashService = mock(HashService.class);
			when(mockHashService.recursiveHash(any())).thenAnswer(
					(Answer<byte[]>) invocationOnMock -> {
						Object[] args = invocationOnMock.getArguments();
						ImmutableList<Hashable> argsList = Arrays.stream(args).map(arg -> (Hashable) arg).collect(toImmutableList());
						HashableList hashables = HashableList.from(argsList);
						BigInteger hashModQ = byteArrayToInteger(hashService.recursiveHash(hashables)).mod(gqGroup.getQ().subtract(BigInteger.ONE))
								.add(BigInteger.ONE);
						return integerToByteArray(hashModQ);
					});
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
			SameGroupVector<GqElement, GqGroup> longerCommitmentsA = gqGroupGenerator.genRandomGqElementVector(m + 1);
			ProductStatement differentSizeStatement = new ProductStatement(longerCommitmentsA, productB);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.getProductArgument(differentSizeStatement, witness));
			assertEquals("The commitments A and the exponents r must have the same size.", exception.getMessage());
		}

		@Test
		@DisplayName("with witness having a size incompatible with the commitment key throws an IllegalArgumentException")
		void getProductArgumentWithWitnessSizeIncompatibleWithCommitmentKeySize() {
			// Create a matrix with too many rows
			SameGroupMatrix<ZqElement, ZqGroup> otherMatrixA = zqGroupGenerator.genRandomZqElementMatrix(k + 1, m);
			ProductWitness otherWitness = new ProductWitness(otherMatrixA, exponentsR);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.getProductArgument(statement, otherWitness));
			assertEquals("The matrix' number of rows cannot be greater than the commitment key size.", exception.getMessage());
		}

		@Test
		@DisplayName("with statement and witness having incompatible groups throws IllegalArgumentException")
		void getProductArgumentWithStatementAndWitnessDifferentGroup() {
			SameGroupVector<GqElement, GqGroup> otherCommitmentsA = otherGqGroupGenerator.genRandomGqElementVector(m);
			ZqElement otherProductB = otherZqGroupGenerator.genRandomZqElementMember();
			ProductStatement otherStatement = new ProductStatement(otherCommitmentsA, otherProductB);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.getProductArgument(otherStatement, witness));
			assertEquals("The product b and the matrix A must belong to the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with commitments and commitment key from different group throws IllegalArgumentException")
		void getProductArgumentWithCommitmentsAndCommitmentKeyFromDifferentGroups() {
			ProductWitness otherWitness = genProductWitness(n, m, otherZqGroupGenerator);
			CommitmentKey otherCommitmentKey = new CommitmentKeyGenerator(otherGqGroup).genCommitmentKey(k);
			ProductStatement otherStatement = getProductStatement(otherWitness, otherCommitmentKey);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.getProductArgument(otherStatement, otherWitness));
			assertEquals("The commitment key and the commitments must have the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with a matrix with 1 column returns only the SingleValueProductArgument")
		void getProductArgumentWithOneColumnMatrix() {
			ProductWitness smallWitness = genProductWitness(n, 1, zqGroupGenerator);
			ProductStatement smallStatement = getProductStatement(smallWitness, commitmentKey);

			ProductArgument argument = assertDoesNotThrow(() -> productArgumentService.getProductArgument(smallStatement, smallWitness));

			// Check that the output is the same as with getSingleValueProductArgument
			assertNull(argument.getCommitmentB());
			assertNull(argument.getHadamardArgument());

			SingleValueProductStatement sStatement = new SingleValueProductStatement(smallStatement.getCommitments().get(0),
					smallStatement.getProduct());
			assertTrue(new SingleValueProductArgumentService(randomService, mockHashService, publicKey, commitmentKey)
					.verifySingleValueProductArgument(sStatement, argument.getSingleValueProductArgument()));
		}

		@Test
		@DisplayName("with incompatible commitment and matrix throws an IllegalArgumentException")
		void getProductArgumentWithBadCommitment() {
			List<GqElement> commitmentList = commitmentsA.stream().collect(Collectors.toCollection(ArrayList::new));
			GqElement g = commitmentsA.getGroup().getGenerator();
			GqElement first = commitmentList.get(0);
			first = first.multiply(g);
			commitmentList.set(0, first);
			SameGroupVector<GqElement, GqGroup> badCommitmentsA = new SameGroupVector<>(commitmentList);
			ProductStatement badStatement = new ProductStatement(badCommitmentsA, productB);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.getProductArgument(badStatement, witness));
			assertEquals("The commitment to matrix A with exponents r using the given commitment key must yield the commitments cA.",
					exception.getMessage());
		}

		@Test
		@DisplayName("with a product that does not correspond to the matrix product throws a IllegalArgumentException")
		void getProductArgumentWithBadProduct() {
			ZqElement one = ZqElement.create(BigInteger.ONE, ZqGroup.sameOrderAs(gqGroup));
			ZqElement badProductB = productB.add(one);
			ProductStatement badStatement = new ProductStatement(commitmentsA, badProductB);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.getProductArgument(badStatement, witness));
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
			ZeroArgument expectedZeroArgument = new ZeroArgument.Builder().withCA0(gqFive)
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
			SingleValueProductArgument expectedSingleValueProductArgument = new SingleValueProductArgument.Builder()
					.withCd(gqFive)
					.withCLowerDelta(gqThree)
					.withCUpperDelta(gqNine)
					.withATilde(SameGroupVector.of(zqFour, zqZero))
					.withBTilde(SameGroupVector.of(zqFour, zqZero))
					.withRTilde(zqThree)
					.withSTilde(zqZero)
					.build();

			// Create the expected ProductArgument
			ProductArgument expectedProductArgument = new ProductArgument(gqNine, expectedHadamardArgument, expectedSingleValueProductArgument);

			assertEquals(expectedProductArgument, specificProductArgumentService.getProductArgument(productStatement, productWitness));
		}
	}

	@Nested
	@DisplayName("verifyProductArgument...")
	class VerifyProductArgumentTest {

		private ProductArgumentService productArgumentService;

		private int n;
		private int m;
		private ProductStatement longStatement;
		private ProductArgument longArgument;
		private ProductStatement shortStatement;
		private ProductArgument shortArgument;

		@BeforeEach
		void setup() {
			n = secureRandom.nextInt(k - 1) + 2;
			m = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS - 2) + 2; // m > 1

			HashService hashServiceMock = mock(HashService.class);
			when(hashServiceMock.recursiveHash(any())).thenAnswer(
					(Answer<byte[]>) invocationOnMock -> {
						Object[] args = invocationOnMock.getArguments();
						ImmutableList<Hashable> argsList = Arrays.stream(args).map(arg -> (Hashable) arg).collect(toImmutableList());
						HashableList hashables = HashableList.from(argsList);
						BigInteger hashModQ = byteArrayToInteger(ProductArgumentServiceTest.this.hashService.recursiveHash(hashables))
								.mod(gqGroup.getQ().subtract(BigInteger.ONE)).add(BigInteger.ONE);
						return integerToByteArray(hashModQ);
					});
			productArgumentService = new ProductArgumentService(randomService, hashServiceMock, publicKey, commitmentKey);

			ProductWitness longWitness = genProductWitness(n, m, zqGroupGenerator);
			longStatement = getProductStatement(longWitness, commitmentKey);
			longArgument = productArgumentService.getProductArgument(longStatement, longWitness);

			ProductWitness shortWitness = genProductWitness(n, 1, zqGroupGenerator);
			shortStatement = getProductStatement(shortWitness, commitmentKey);
			shortArgument = productArgumentService.getProductArgument(shortStatement, shortWitness);
		}

		@Test
		@DisplayName("with null arguments throws a NullPointerException")
		void verifyProductArgumentWithNullArguments() {
			assertThrows(NullPointerException.class, () -> productArgumentService.verifyProductArgument(null, longArgument));
			assertThrows(NullPointerException.class, () -> productArgumentService.verifyProductArgument(longStatement, null));
		}

		@Test
		@DisplayName("with null cb when m > 1 throws a NullPointerException")
		void verifyProductArgumentWithNullCb() {
			ProductArgument argumentWithNullCb = spy(longArgument);
			when(argumentWithNullCb.getCommitmentB()).thenReturn(null);
			Exception exception = assertThrows(NullPointerException.class, () -> productArgumentService.verifyProductArgument(longStatement, argumentWithNullCb));
			assertEquals("The product argument must contain a commitment b for m > 1.", exception.getMessage());
		}

		@Test
		@DisplayName("with null HadamardArgument when m > 1 throws a NullPointerException")
		void verifyProductArgumentWithNullHadamardArgument() {
			ProductArgument argumentWithNullHadamard = spy(longArgument);
			when(argumentWithNullHadamard.getHadamardArgument()).thenReturn(null);
			Exception exception = assertThrows(NullPointerException.class, () -> productArgumentService.verifyProductArgument(longStatement, argumentWithNullHadamard));
			assertEquals("The product argument must contain a Hadamard argument for m > 1.", exception.getMessage());
		}

		@Test
		@DisplayName("with statement and argument having different groups throws an IllegalArgumentException")
		void verifyProductArgumentWithStatementAndArgumentFromDifferentGroups() {
			ProductWitness otherWitness = genProductWitness(n, m, otherZqGroupGenerator);
			CommitmentKey otherCommitmentKey = new CommitmentKeyGenerator(otherGqGroup).genCommitmentKey(k);
			ProductStatement otherStatement = getProductStatement(otherWitness, otherCommitmentKey);

			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.verifyProductArgument(otherStatement, longArgument));
			assertEquals("The statement and the argument must have compatible groups.", exception.getMessage());
		}

		@Test
		@DisplayName("with statement and argument having different sizes throws an IllegalArgumentException")
		void verifyProductArgumentWithStatementAndArgumentOfDifferentSizes() {
			ProductWitness otherWitness = genProductWitness(n, m + 1, zqGroupGenerator);
			ProductStatement otherStatement = getProductStatement(otherWitness, commitmentKey);

			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.verifyProductArgument(otherStatement, longArgument));
			assertEquals("The statement and the argument must have the same m.",
					exception.getMessage());
		}

		@Test
		@DisplayName("with correct input returns true")
		void verifyProductArgumentWithCorrectInput() {
			assertTrue(productArgumentService.verifyProductArgument(longStatement, longArgument));
			assertTrue(productArgumentService.verifyProductArgument(shortStatement, shortArgument));
		}

		@Test
		@DisplayName("with an incorrect c_b returns false")
		void verifyProductArgumentWithBadCommitment() {
			GqElement badCommitment = longArgument.getCommitmentB();
			badCommitment = badCommitment.multiply(gqGroup.getGenerator());
			ProductArgument badArgument = new ProductArgument(badCommitment, longArgument.getHadamardArgument(),
					longArgument.getSingleValueProductArgument());
			assertFalse(productArgumentService.verifyProductArgument(longStatement, badArgument));
		}

		@Test
		@DisplayName("with an incorrect HadamardArgument returns false")
		void verifyProductArgumentWithBadHadamardArgument() {
			HadamardArgument hadamardArgument = longArgument.getHadamardArgument();
			SameGroupVector<GqElement, GqGroup> cUpperB = hadamardArgument.getCommitmentsB();

			GqElement badcUpperB0 = cUpperB.get(0).multiply(gqGroup.getGenerator());
			SameGroupVector<GqElement, GqGroup> badcUpperB = cUpperB.stream().skip(1).collect(toSameGroupVector()).prepend(badcUpperB0);
			HadamardArgument badHadamardArgument = new HadamardArgument(badcUpperB, hadamardArgument.getZeroArgument());
			ProductArgument badArgument = new ProductArgument(longArgument.getCommitmentB(), badHadamardArgument,
					longArgument.getSingleValueProductArgument());

			assertFalse(productArgumentService.verifyProductArgument(longStatement, badArgument));
		}

		@Test
		@DisplayName("with an incorrect SingleValueProductArgument (m >= 2) returns false")
		void verifyProductArgumentWithBadSingleValueProductArgumentMGreaterThanOne() {
			SingleValueProductArgument sArgument = longArgument.getSingleValueProductArgument();
			ZqElement rTilde = sArgument.getRTilde();

			ZqElement badRTilde = rTilde.add(ZqElement.create(BigInteger.ONE, zqGroup));
			SingleValueProductArgument badSArgument = new SingleValueProductArgument.Builder()
					.withCd(sArgument.getCd())
					.withCLowerDelta(sArgument.getCLowerDelta())
					.withCUpperDelta(sArgument.getCUpperDelta())
					.withATilde(sArgument.getATilde())
					.withBTilde(sArgument.getBTilde())
					.withRTilde(badRTilde)
					.withSTilde(sArgument.getSTilde())
					.build();
			ProductArgument badArgument = new ProductArgument(longArgument.getCommitmentB(), longArgument.getHadamardArgument(), badSArgument);
			assertFalse(productArgumentService.verifyProductArgument(longStatement, badArgument));
		}

		@Test
		@DisplayName("with an incorrect SingleValueProductArgument (m = 1) returns false")
		void verifyProductArgumentWithBadSingleValueProductArgumentMEqualsOne() {
			SingleValueProductArgument sArgument = shortArgument.getSingleValueProductArgument();
			ZqElement rTilde = sArgument.getRTilde();

			ZqElement badRTilde = rTilde.add(ZqElement.create(BigInteger.ONE, zqGroup));
			SingleValueProductArgument badSArgument = new SingleValueProductArgument.Builder()
					.withCd(sArgument.getCd())
					.withCLowerDelta(sArgument.getCLowerDelta())
					.withCUpperDelta(sArgument.getCUpperDelta())
					.withATilde(sArgument.getATilde())
					.withBTilde(sArgument.getBTilde())
					.withRTilde(badRTilde)
					.withSTilde(sArgument.getSTilde())
					.build();
			ProductArgument badArgument = new ProductArgument(badSArgument);

			assertFalse(productArgumentService.verifyProductArgument(shortStatement, badArgument));
		}

	}
}