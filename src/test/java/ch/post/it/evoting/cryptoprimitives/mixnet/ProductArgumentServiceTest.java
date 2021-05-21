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

import static ch.post.it.evoting.cryptoprimitives.GroupVector.toGroupVector;
import static ch.post.it.evoting.cryptoprimitives.mixnet.TestProductGenerator.genProductWitness;
import static ch.post.it.evoting.cryptoprimitives.mixnet.TestProductGenerator.getProductStatement;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doReturn;
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
import java.util.Optional;
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

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

class ProductArgumentServiceTest extends TestGroupSetup {

	private static final int BOUND_FOR_RANDOM_ELEMENTS = 10;
	private static final RandomService randomService = new RandomService();
	private static final SecureRandom secureRandom = new SecureRandom();

	private static int k;
	private static int mu;
	private static HashService hashService;
	private static ElGamalMultiRecipientPublicKey publicKey;
	private static CommitmentKey commitmentKey;

	@BeforeAll
	static void setupAll() {
		k = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS - 1) + 1;
		mu = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS - 2) + 2;

		hashService = TestHashService.create(gqGroup.getQ());
		publicKey = new ElGamalGenerator(gqGroup).genRandomPublicKey(k);

		commitmentKey = new TestCommitmentKeyGenerator(gqGroup).genCommitmentKey(mu);
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
		@DisplayName("a hashService that has a too long hash length throws an IllegalArgumentException")
		void constructWithHashServiceWithTooLongHashLength() throws NoSuchAlgorithmException {
			HashService otherHashService = new HashService(MessageDigest.getInstance("SHA-256"));
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> new ProductArgumentService(randomService, otherHashService, publicKey, commitmentKey));
			assertEquals("The hash service's bit length must be smaller than the bit length of q.", exception.getMessage());
		}

		@Test
		@DisplayName("with public key from different group than commitment key throws an IllegalArgumentException")
		void constructProductArgumentWithPublicKeyGroupDifferentCommitmentKeyGroup() {
			ElGamalMultiRecipientPublicKey otherPublicKey = new ElGamalGenerator(otherGqGroup).genRandomPublicKey(k);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> new ProductArgumentService(randomService, hashService, otherPublicKey, commitmentKey));
			assertEquals("The public key and the commitment key must have the same group.", exception.getMessage());
		}
	}

	@Nested
	@DisplayName("getProductArgument...")
	class GetProductArgumentTest {

		private int n;
		private int m;
		private GroupVector<GqElement, GqGroup> commitmentsA;
		private ZqElement productB;
		private ProductStatement statement;
		private GroupVector<ZqElement, ZqGroup> exponentsR;
		private ProductWitness witness;
		private ProductArgumentService productArgumentService;

		@BeforeEach
		void setup() {
			n = secureRandom.nextInt(mu - 1) + 2;
			m = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS) + 1;

			witness = genProductWitness(n, m, zqGroupGenerator);
			exponentsR = witness.getExponents();
			statement = getProductStatement(witness, commitmentKey);
			commitmentsA = statement.getCommitments();
			productB = statement.getProduct();

			productArgumentService = new ProductArgumentService(randomService, hashService, publicKey, commitmentKey);
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
			GroupVector<GqElement, GqGroup> longerCommitmentsA = gqGroupGenerator.genRandomGqElementVector(m + 1);
			ProductStatement differentSizeStatement = new ProductStatement(longerCommitmentsA, productB);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.getProductArgument(differentSizeStatement, witness));
			assertEquals("The commitments A and the exponents r must have the same size.", exception.getMessage());
		}

		@Test
		@DisplayName("with witness having a size incompatible with the commitment key throws an IllegalArgumentException")
		void getProductArgumentWithWitnessSizeIncompatibleWithCommitmentKeySize() {
			// Create a matrix with too many rows
			GroupMatrix<ZqElement, ZqGroup> otherMatrixA = zqGroupGenerator.genRandomZqElementMatrix(mu + 1, m);
			ProductWitness otherWitness = new ProductWitness(otherMatrixA, exponentsR);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.getProductArgument(statement, otherWitness));
			assertEquals("The matrix' number of rows cannot be greater than the commitment key size.", exception.getMessage());
		}

		@Test
		@DisplayName("with statement and witness having incompatible groups throws IllegalArgumentException")
		void getProductArgumentWithStatementAndWitnessDifferentGroup() {
			GroupVector<GqElement, GqGroup> otherCommitmentsA = otherGqGroupGenerator.genRandomGqElementVector(m);
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
			CommitmentKey otherCommitmentKey = new TestCommitmentKeyGenerator(otherGqGroup).genCommitmentKey(mu);
			ProductStatement otherStatement = getProductStatement(otherWitness, otherCommitmentKey);
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.getProductArgument(otherStatement, otherWitness));
			assertEquals("The commitment key and the commitments must have the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with a matrix with 1 row throws an IllegalArgumentException")
		void getProductArgumentWithOneRowMatrix() {
			ProductWitness smallWitness = genProductWitness(1, m, zqGroupGenerator);
			ProductStatement smallStatement = getProductStatement(smallWitness, commitmentKey);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.getProductArgument(smallStatement, smallWitness));
			assertEquals("The number of rows n must be greater than or equal to 2.", exception.getMessage());
		}

		@Test
		@DisplayName("with a matrix with 1 column returns only the SingleValueProductArgument")
		void getProductArgumentWithOneColumnMatrix() {
			ProductWitness smallWitness = genProductWitness(n, 1, zqGroupGenerator);
			ProductStatement smallStatement = getProductStatement(smallWitness, commitmentKey);

			ProductArgument argument = assertDoesNotThrow(() -> productArgumentService.getProductArgument(smallStatement, smallWitness));

			// Check that the output is the same as with getSingleValueProductArgument
			assertFalse(argument.getCommitmentB().isPresent());
			assertFalse(argument.getHadamardArgument().isPresent());

			SingleValueProductStatement sStatement = new SingleValueProductStatement(smallStatement.getCommitments().get(0),
					smallStatement.getProduct());
			assertTrue(new SingleValueProductArgumentService(randomService, hashService, publicKey, commitmentKey)
					.verifySingleValueProductArgument(sStatement, argument.getSingleValueProductArgument()).verify().isVerified());
		}

		@Test
		@DisplayName("with incompatible commitment and matrix throws an IllegalArgumentException")
		void getProductArgumentWithBadCommitment() {
			List<GqElement> commitmentList = new ArrayList<>(commitmentsA);
			GqElement g = commitmentsA.getGroup().getGenerator();
			GqElement first = commitmentList.get(0);
			first = first.multiply(g);
			commitmentList.set(0, first);
			commitmentsA = GroupVector.from(commitmentList);
			statement = new ProductStatement(commitmentsA, productB);
			Exception exception = assertThrows(IllegalArgumentException.class, () -> productArgumentService.getProductArgument(statement, witness));
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
			RandomService productRandomService = spy(RandomService.class);
			HashService productHashService = mock(HashService.class);

			BigInteger zero = BigInteger.ZERO;
			BigInteger one = BigInteger.ONE;
			BigInteger two = BigInteger.valueOf(2);
			BigInteger three = BigInteger.valueOf(3);
			BigInteger four = BigInteger.valueOf(4);

			doReturn(four, // s
					three, // s_1
					one, three, // a_0
					two, one, // b_m
					four, // r_0
					zero, // s_m
					zero, one, three, four, two, one, two, // t
					four, one, zero, // d_0, d_1, r_d
					one, two // s_0, s_x
			).when(productRandomService).genRandomInteger(any());
			when(productHashService.recursiveHash(any()))
					.thenReturn(new byte[] { 0b10 }, new byte[] { 0b11 }, new byte[] { 0b01 }, new byte[] { 0b10 });
			ProductArgumentService specificProductArgumentService = new ProductArgumentService(productRandomService, productHashService,
					productPublicKey, productCommitmentKey);

			// Create A and r
			List<List<ZqElement>> matrixColumns = new ArrayList<>(m);
			matrixColumns.add(0, Arrays.asList(zqOne, zqThree));
			matrixColumns.add(1, Arrays.asList(zqTwo, zqFour));
			matrixColumns.add(2, Arrays.asList(zqZero, zqOne));
			GroupMatrix<ZqElement, ZqGroup> matrix = GroupMatrix.fromColumns(matrixColumns);
			GroupVector<ZqElement, ZqGroup> exponents = GroupVector.from(Arrays.asList(zqOne, zqTwo, zqFour));

			ProductWitness productWitness = new ProductWitness(matrix, exponents);

			// Calculate c_A and b
			GroupVector<GqElement, GqGroup> commitmentsA = CommitmentService.getCommitmentMatrix(matrix, exponents, productCommitmentKey);
			ZqElement product = matrix.stream().reduce(zqOne, ZqElement::multiply);

			ProductStatement productStatement = new ProductStatement(commitmentsA, product);

			// Create the expected zeroArgument
			ZeroArgument expectedZeroArgument = new ZeroArgument.Builder().withCA0(gqFive)
					.withCBm(gqOne)
					.withCd(GroupVector.of(gqNine, gqFive, gqThree, gqThree, gqOne, gqFour, gqFour))
					.withAPrime(GroupVector.of(zqTwo, zqTwo))
					.withBPrime(GroupVector.of(zqOne, zqTwo))
					.withRPrime(zqZero)
					.withSPrime(zqOne)
					.withTPrime(zqOne)
					.build();

			// Create the Hadamard product argument's expected c_(B_0), c_(B_1), c_(B_2)
			GroupVector<GqElement, GqGroup> commitmentsB = GroupVector.of(gqNine, gqFive, gqNine);
			// Create the expected HadamardArgument
			HadamardArgument expectedHadamardArgument = new HadamardArgument(commitmentsB, expectedZeroArgument);

			// Create the expected SingleValueProductArgument
			SingleValueProductArgument expectedSingleValueProductArgument = new SingleValueProductArgument.Builder()
					.withCd(gqFive)
					.withCLowerDelta(gqThree)
					.withCUpperDelta(gqNine)
					.withATilde(GroupVector.of(zqFour, zqZero))
					.withBTilde(GroupVector.of(zqFour, zqZero))
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
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VerifyProductArgumentTest {

		private final ProductArgumentService productArgumentService = new ProductArgumentService(randomService, hashService, publicKey,
				commitmentKey);

		private int n;

		@BeforeEach
		void setup() {
			n = secureRandom.nextInt(mu - 1) + 2;
		}

		Stream<Arguments> statementArgumentProvider() {
			final int n = secureRandom.nextInt(mu - 1) + 2;

			// Create ProductStatement and ProductArgument for testing with m > 1
			final int m = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS - 2) + 2;
			ProductWitness longWitness = genProductWitness(n, m, zqGroupGenerator);
			ProductStatement longStatement = getProductStatement(longWitness, commitmentKey);
			ProductArgument longArgument = productArgumentService.getProductArgument(longStatement, longWitness);

			// Create ProductStatement and ProductArgument for testing with m = 1
			ProductWitness shortWitness = genProductWitness(n, 1, zqGroupGenerator);
			ProductStatement shortStatement = getProductStatement(shortWitness, commitmentKey);
			ProductArgument shortArgument = productArgumentService.getProductArgument(shortStatement, shortWitness);

			return Stream.of(
					Arguments.of(longStatement, longArgument),
					Arguments.of(shortStatement, shortArgument)
			);
		}

		@ParameterizedTest
		@MethodSource("statementArgumentProvider")
		@DisplayName("with null arguments throws a NullPointerException")
		void verifyProductArgumentMGreaterOneWithNullArguments(final ProductStatement statement, final ProductArgument argument) {
			assertThrows(NullPointerException.class, () -> productArgumentService.verifyProductArgument(null, argument));
			assertThrows(NullPointerException.class, () -> productArgumentService.verifyProductArgument(statement, null));
		}

		@Test
		@DisplayName("with null cb when m > 1 throws a NullPointerException")
		void verifyProductArgumentWithNullCb() {
			final int m = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS - 2) + 2; // m > 1
			ProductWitness longWitness = genProductWitness(n, m, zqGroupGenerator);
			ProductStatement longStatement = getProductStatement(longWitness, commitmentKey);
			ProductArgument longArgument = productArgumentService.getProductArgument(longStatement, longWitness);

			ProductArgument argumentWithNullCb = spy(longArgument);
			when(argumentWithNullCb.getCommitmentB()).thenReturn(Optional.empty());
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.verifyProductArgument(longStatement, argumentWithNullCb));
			assertEquals("The product argument must contain a commitment b for m > 1.", exception.getMessage());
		}

		@Test
		@DisplayName("with null HadamardArgument when m > 1 throws a NullPointerException")
		void verifyProductArgumentWithNullHadamardArgument() {
			final int m = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS - 2) + 2;
			ProductWitness longWitness = genProductWitness(n, m, zqGroupGenerator);
			ProductStatement longStatement = getProductStatement(longWitness, commitmentKey);
			ProductArgument longArgument = productArgumentService.getProductArgument(longStatement, longWitness);

			ProductArgument argumentWithNullHadamard = spy(longArgument);
			when(argumentWithNullHadamard.getHadamardArgument()).thenReturn(Optional.empty());
			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.verifyProductArgument(longStatement, argumentWithNullHadamard));
			assertEquals("The product argument must contain a Hadamard argument for m > 1.", exception.getMessage());
		}

		@ParameterizedTest
		@MethodSource("statementArgumentProvider")
		@DisplayName("with statement and argument having different groups throws an IllegalArgumentException")
		void verifyProductArgumentWithStatementAndArgumentFromDifferentGroups(final ProductStatement statement, final ProductArgument argument) {
			final int m = argument.getM();
			ProductWitness otherWitness = genProductWitness(n, m, otherZqGroupGenerator);
			CommitmentKey otherCommitmentKey = new TestCommitmentKeyGenerator(otherGqGroup).genCommitmentKey(mu);
			ProductStatement otherStatement = getProductStatement(otherWitness, otherCommitmentKey);

			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.verifyProductArgument(otherStatement, argument));
			assertEquals("The statement and the argument must have compatible groups.", exception.getMessage());
		}

		@ParameterizedTest
		@MethodSource("statementArgumentProvider")
		@DisplayName("with statement and argument having different sizes throws an IllegalArgumentException")
		void verifyProductArgumentWithStatementAndArgumentOfDifferentSizes(final ProductStatement statement, final ProductArgument argument) {
			final int m = argument.getM();
			ProductWitness otherWitness = genProductWitness(n, m + 1, zqGroupGenerator);
			ProductStatement otherStatement = getProductStatement(otherWitness, commitmentKey);

			Exception exception = assertThrows(IllegalArgumentException.class,
					() -> productArgumentService.verifyProductArgument(otherStatement, argument));
			assertEquals("The statement and the argument must have the same m.",
					exception.getMessage());
		}

		@ParameterizedTest
		@MethodSource("statementArgumentProvider")
		@DisplayName("with correct input returns true")
		void verifyProductArgumentWithCorrectInput(final ProductStatement statement, final ProductArgument argument) {
			assertTrue(productArgumentService.verifyProductArgument(statement, argument).verify().isVerified());
		}

		@Test
		@DisplayName("with an incorrect c_b returns false")
		void verifyProductArgumentWithBadCommitment() {
			final int m = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS - 2) + 2;
			ProductWitness longWitness = genProductWitness(n, m, zqGroupGenerator);
			ProductStatement longStatement = getProductStatement(longWitness, commitmentKey);
			ProductArgument longArgument = productArgumentService.getProductArgument(longStatement, longWitness);

			GqElement badCommitment = longArgument.getCommitmentB().orElseThrow(() -> new IllegalArgumentException("Missing commitmentB"));
			badCommitment = badCommitment.multiply(gqGroup.getGenerator());
			ProductArgument badArgument = new ProductArgument(badCommitment,
					longArgument.getHadamardArgument().orElseThrow(() -> new IllegalArgumentException("Missing HadamardArgument")),
					longArgument.getSingleValueProductArgument());

			final VerificationResult verificationResult = productArgumentService.verifyProductArgument(longStatement, badArgument).verify();
			assertFalse(verificationResult.isVerified());
			assertEquals("Failed to verify Hadamard Argument.", verificationResult.getErrorMessages().element());
		}

		@Test
		@DisplayName("with an incorrect HadamardArgument returns false")
		void verifyProductArgumentWithBadHadamardArgument() {
			final int m = secureRandom.nextInt(BOUND_FOR_RANDOM_ELEMENTS - 2) + 2; // m > 1
			ProductWitness longWitness = genProductWitness(n, m, zqGroupGenerator);
			ProductStatement longStatement = getProductStatement(longWitness, commitmentKey);
			ProductArgument longArgument = productArgumentService.getProductArgument(longStatement, longWitness);

			HadamardArgument hadamardArgument = longArgument.getHadamardArgument()
					.orElseThrow(() -> new IllegalArgumentException("Missing HadamardArgument"));
			GroupVector<GqElement, GqGroup> cUpperB = hadamardArgument.getCommitmentsB();

			GqElement badcUpperB0 = cUpperB.get(0).multiply(gqGroup.getGenerator());
			GroupVector<GqElement, GqGroup> badcUpperB = cUpperB.stream().skip(1).collect(toGroupVector()).prepend(badcUpperB0);
			HadamardArgument badHadamardArgument = new HadamardArgument(badcUpperB, hadamardArgument.getZeroArgument());
			ProductArgument badArgument = new ProductArgument(
					longArgument.getCommitmentB().orElseThrow(() -> new IllegalArgumentException("Missing commitmentB")),
					badHadamardArgument, longArgument.getSingleValueProductArgument());

			final VerificationResult verificationResult = productArgumentService.verifyProductArgument(longStatement, badArgument).verify();
			assertFalse(verificationResult.isVerified());
			assertEquals("Failed to verify Hadamard Argument.", verificationResult.getErrorMessages().element());
		}

		@ParameterizedTest
		@MethodSource("statementArgumentProvider")
		@DisplayName("with an incorrect SingleValueProductArgument returns false")
		void verifyProductArgumentWithBadSingleValueProductArgument(final ProductStatement statement, final ProductArgument argument) {
			SingleValueProductArgument sArgument = argument.getSingleValueProductArgument();
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
			ProductArgument badArgument;
			if (argument.getCommitmentB().isPresent() && argument.getHadamardArgument().isPresent()) {
				badArgument = new ProductArgument(argument.getCommitmentB().get(), argument.getHadamardArgument().get(), badSArgument);
			} else {
				badArgument = new ProductArgument(badSArgument);
			}

			final VerificationResult verificationResult = productArgumentService.verifyProductArgument(statement, badArgument).verify();
			assertFalse(verificationResult.isVerified());
			assertEquals("Failed to verify Single Value Product Argument.", verificationResult.getErrorMessages().element());
		}

		@ParameterizedTest(name = "{5}")
		@MethodSource("verifyProductArgumentRealValuesProvider")
		@DisplayName("with real values gives expected result")
		void verifyProductArgumentRealValues(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey,
				final ProductStatement productStatement, final ProductArgument productArgument, final boolean expectedOutput,
				final String description) throws NoSuchAlgorithmException {

			final HashService hashService = new HashService(MessageDigest.getInstance("SHA-256"));

			final ProductArgumentService productArgumentService = new ProductArgumentService(randomService, hashService, publicKey,
					commitmentKey);

			assertEquals(expectedOutput, productArgumentService.verifyProductArgument(productStatement, productArgument).verify().isVerified(),
					String.format("assertion failed for: %s", description));
		}

		Stream<Arguments> verifyProductArgumentRealValuesProvider() {
			final List<TestParameters> parametersList = TestParameters.fromResource("/mixnet/verify-product-argument.json");

			return parametersList.stream().parallel().map(testParameters -> {
				// TestContextParser.
				final JsonData contextData = testParameters.getContext();
				final TestContextParser context = new TestContextParser(contextData);

				final GqGroup realGqGroup = context.getGqGroup();
				final ElGamalMultiRecipientPublicKey realPublicKey = context.parsePublicKey();
				final CommitmentKey realCommitmentKey = context.parseCommitmentKey();

				// Inputs.
				final JsonData input = testParameters.getInput();
				final JsonData statement = input.getJsonData("statement");
				final JsonData argument = input.getJsonData("argument");

				final ProductStatement productStatement = parseProductStatement(realGqGroup, statement);

				// Product Argument.
				ProductArgument productArgument = new TestArgumentParser(realGqGroup).parseProductArgument(argument);

				// Output.
				final JsonData output = testParameters.getOutput();
				final boolean outputValue = output.get("verif_result", Boolean.class);

				return Arguments
						.of(realPublicKey, realCommitmentKey, productStatement, productArgument, outputValue, testParameters.getDescription());
			});
		}

		private ProductStatement parseProductStatement(final GqGroup realGqGroup, final JsonData statement) {
			final BigInteger[] cAValues = statement.get("c_a", BigInteger[].class);
			final BigInteger bValue = statement.get("b", BigInteger.class);
			final GroupVector<GqElement, GqGroup> commitments = Arrays.stream(cAValues)
					.map(bi -> GqElement.create(bi, realGqGroup))
					.collect(toGroupVector());
			final ZqElement product = ZqElement.create(bValue, ZqGroup.sameOrderAs(realGqGroup));

			return new ProductStatement(commitments, product);
		}

	}

}
