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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static ch.post.it.evoting.cryptoprimitives.mixnet.TestParser.parseCommitment;
import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
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
import org.mockito.Mockito;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.TestHashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.Generators;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

@DisplayName("A ZeroArgumentService")
class ZeroArgumentServiceTest extends TestGroupSetup {

	private static final BigInteger ZERO = BigInteger.valueOf(0);
	private static final BigInteger ONE = BigInteger.ONE;
	private static final BigInteger TWO = BigInteger.valueOf(2);
	private static final BigInteger THREE = BigInteger.valueOf(3);
	private static final BigInteger FOUR = BigInteger.valueOf(4);
	private static final BigInteger FIVE = BigInteger.valueOf(5);
	private static final BigInteger SIX = BigInteger.valueOf(6);
	private static final BigInteger SEVEN = BigInteger.valueOf(7);
	private static final BigInteger EIGHT = BigInteger.valueOf(8);
	private static final BigInteger NINE = BigInteger.valueOf(9);
	private static final BigInteger TEN = BigInteger.TEN;
	private static final BigInteger ELEVEN = BigInteger.valueOf(11);
	private static final int KEY_ELEMENTS_NUMBER = 10;
	private static final SecureRandom secureRandom = new SecureRandom();

	private static ZeroArgumentService zeroArgumentService;
	private static CommitmentKey commitmentKey;
	private static ElGamalMultiRecipientPublicKey publicKey;
	private static RandomService randomService;
	private static HashService hashService;

	@BeforeAll
	static void setUpAll() throws Exception {
		// Generate publicKey and commitmentKey.
		final TestCommitmentKeyGenerator commitmentKeyGenerator = new TestCommitmentKeyGenerator(gqGroup);
		commitmentKey = commitmentKeyGenerator.genCommitmentKey(KEY_ELEMENTS_NUMBER);

		final ElGamalGenerator elGamalGenerator = new ElGamalGenerator(gqGroup);
		publicKey = elGamalGenerator.genRandomPublicKey(KEY_ELEMENTS_NUMBER);

		// Init services.
		randomService = new RandomService();
		hashService = TestHashService.create(gqGroup.getQ());

		zeroArgumentService = new ZeroArgumentService(publicKey, commitmentKey, randomService, hashService);
	}

	@Test
	@DisplayName("constructed with any null parameter throws NullPointerException")
	void constructNullParams() {
		assertAll(
				() -> assertThrows(NullPointerException.class,
						() -> new ZeroArgumentService(null, commitmentKey, randomService, hashService)),
				() -> assertThrows(NullPointerException.class,
						() -> new ZeroArgumentService(publicKey, null, randomService, hashService)),
				() -> assertThrows(NullPointerException.class,
						() -> new ZeroArgumentService(publicKey, commitmentKey, null, hashService)),
				() -> assertThrows(NullPointerException.class,
						() -> new ZeroArgumentService(publicKey, commitmentKey, randomService, null))
		);
	}

	@Test
	@DisplayName("Constructing a ZeroArgumentService with a hashService that has a too long hash length throws an IllegalArgumentException")
	void constructWithHashServiceWithTooLongHashLength() {
		final HashService otherHashService = HashService.getInstance();
		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroArgumentService(publicKey, commitmentKey, randomService, otherHashService));
		assertEquals("The hash service's bit length must be smaller than the bit length of q.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with keys from different groups throws IllegalArgumentException")
	void constructDiffGroupKeys() {
		// Create public key from other group.
		final ElGamalMultiRecipientPublicKey otherPublicKey = new ElGamalGenerator(otherGqGroup).genRandomPublicKey(KEY_ELEMENTS_NUMBER);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroArgumentService(otherPublicKey, commitmentKey, randomService, hashService));
		assertEquals("The public and commitment keys are not from the same group.", exception.getMessage());
	}

	@Nested
	@DisplayName("computeDVector")
	class ComputeDVectorTest {

		private static final int RANDOM_UPPER_BOUND = 10;

		private int n;
		private int m;
		private GroupMatrix<ZqElement, ZqGroup> firstMatrix;
		private GroupMatrix<ZqElement, ZqGroup> secondMatrix;
		private ZqElement y;

		@BeforeEach
		void setUp() {
			n = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;
			m = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;
			firstMatrix = zqGroupGenerator.genRandomZqElementMatrix(n, m + 1);
			secondMatrix = zqGroupGenerator.genRandomZqElementMatrix(n, m + 1);
			y = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void computeDVectorNullParams() {
			assertAll(
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.computeDVector(null, secondMatrix, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.computeDVector(firstMatrix, null, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.computeDVector(firstMatrix, secondMatrix, null))
			);
		}

		@Test
		@DisplayName("with matrices having unequal number of rows throws IllegalArgumentException")
		void computeDVectorDifferentSizeLines() {
			// Generate a first matrix with an additional row.
			final GroupMatrix<ZqElement, ZqGroup> otherMatrix = zqGroupGenerator.genRandomZqElementMatrix(n + 1, m + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(otherMatrix, secondMatrix, y));
			assertEquals("The two matrices must have the same number of rows.", exception.getMessage());
		}

		@Test
		@DisplayName("with matrices with different number of columns throws IllegalArgumentException")
		void computeDVectorDifferentSizeColumns() {
			final GroupMatrix<ZqElement, ZqGroup> otherFirstMatrix = zqGroupGenerator.genRandomZqElementMatrix(n, m);
			final GroupMatrix<ZqElement, ZqGroup> otherSecondMatrix = zqGroupGenerator.genRandomZqElementMatrix(n, m + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(otherFirstMatrix, otherSecondMatrix, y));
			assertEquals("The two matrices must have the same number of columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with second matrix having elements of different group than the first matrix throws IllegalArgumentException")
		void computeDVectorMatricesDifferentGroup() {
			// Get a second matrix in a different ZqGroup.
			final GroupMatrix<ZqElement, ZqGroup> differentGroupSecondMatrix = otherZqGroupGenerator.genRandomZqElementMatrix(n, m + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(firstMatrix, differentGroupSecondMatrix, y));
			assertEquals("The elements of both matrices must be in the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with y from a different group throws IllegalArgumentException")
		void computeDVectorYDifferentGroup() {
			// Create a y value from a different group.
			final ZqElement differentGroupY = ZqElement.create(randomService.genRandomInteger(otherZqGroup.getQ()), otherZqGroup);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.computeDVector(firstMatrix, secondMatrix, differentGroupY));
			assertEquals("The value y must be in the same group as the elements of the matrices.", exception.getMessage());
		}

		@RepeatedTest(100)
		@DisplayName("with random values gives expected d vector length")
		void computeDVectorTest() {
			assertEquals(2 * m + 1, zeroArgumentService.computeDVector(firstMatrix, secondMatrix, y).size());
		}

		@Test
		@DisplayName("with simple values gives expected result")
		void computeDVectorSimpleValuesTest() {
			// Small Zq group.
			final ZqGroup group = new ZqGroup(ELEVEN);

			// Construct the two matrices and value y.
			final List<ZqElement> a0 = asList(ZqElement.create(ZERO, group), ZqElement.create(TWO, group));
			final List<ZqElement> a1 = asList(ZqElement.create(FOUR, group), ZqElement.create(SIX, group));
			final List<ZqElement> b0 = asList(ZqElement.create(ONE, group), ZqElement.create(THREE, group));
			final List<ZqElement> b1 = asList(ZqElement.create(FIVE, group), ZqElement.create(SEVEN, group));
			final GroupMatrix<ZqElement, ZqGroup> firstMatrix = GroupMatrix.fromRows(asList(a0, a1));
			final GroupMatrix<ZqElement, ZqGroup> secondMatrix = GroupMatrix.fromRows(asList(b0, b1));
			final ZqElement y = ZqElement.create(EIGHT, group);

			// Expected d vector.
			final GroupVector<ZqElement, ZqGroup> expected = GroupVector.of(
					ZqElement.create(TEN, group), ZqElement.create(ONE, group), ZqElement.create(ZERO, group));

			assertEquals(expected, zeroArgumentService.computeDVector(firstMatrix, secondMatrix, y));
		}
	}

	@Nested
	@DisplayName("starMap")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class StarMapTest {

		private static final int RANDOM_UPPER_BOUND = 10;

		private int n;
		private GroupVector<ZqElement, ZqGroup> firstVector;
		private GroupVector<ZqElement, ZqGroup> secondVector;
		private ZqElement y;

		@BeforeEach
		void setUp() {
			n = secureRandom.nextInt(RANDOM_UPPER_BOUND) + 1;
			firstVector = zqGroupGenerator.genRandomZqElementVector(n);
			secondVector = zqGroupGenerator.genRandomZqElementVector(n);
			y = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void starMapNullParams() {
			final GroupVector<ZqElement, ZqGroup> emptyVector = GroupVector.of();

			assertAll(
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.starMap(null, secondVector, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.starMap(firstVector, null, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.starMap(firstVector, secondVector, null)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.starMap(null, emptyVector, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.starMap(emptyVector, null, y)),
					() -> assertThrows(NullPointerException.class, () -> zeroArgumentService.starMap(emptyVector, emptyVector, null))
			);
		}

		@Test
		@DisplayName("with vectors of different size throws IllegalArgumentException")
		void starMapVectorsDifferentSize() {
			final GroupVector<ZqElement, ZqGroup> secondVector = zqGroupGenerator.genRandomZqElementVector(n + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, secondVector, y));
			assertEquals("The provided vectors must have the same size.", exception.getMessage());

			// With empty vectors.
			final GroupVector<ZqElement, ZqGroup> emptyVector = GroupVector.of();
			final IllegalArgumentException exceptionSecondEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, emptyVector, y));
			assertEquals("The provided vectors must have the same size.", exceptionSecondEmpty.getMessage());

			final IllegalArgumentException exceptionFirstEmpty = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(emptyVector, secondVector, y));
			assertEquals("The provided vectors must have the same size.", exceptionFirstEmpty.getMessage());
		}

		@Test
		@DisplayName("with second vector elements of different group than the first vector throws IllegalArgumentException")
		void starMapVectorsDifferentGroup() {
			// Second vector from different group.
			final GroupVector<ZqElement, ZqGroup> secondVector = otherZqGroupGenerator.genRandomZqElementVector(n);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, secondVector, y));
			assertEquals("The elements of both vectors must be in the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("constructed with value y from different group throws IllegalArgumentException")
		void starMapYDifferentGroup() {
			// Get another y from a different group.
			final ZqElement differentGroupY = otherZqGroupGenerator.genRandomZqElementMember();

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.starMap(firstVector, secondVector, differentGroupY));
			assertEquals("The value y must be in the same group as the vectors elements", exception.getMessage());
		}

		@Test
		@DisplayName("with empty vectors returns identity")
		void starMapEmptyVectors() {
			final GroupVector<ZqElement, ZqGroup> firstVector = GroupVector.of();
			final GroupVector<ZqElement, ZqGroup> secondVector = GroupVector.of();

			assertEquals(zqGroup.getIdentity(), zeroArgumentService.starMap(firstVector, secondVector, y));
		}

		@Test
		@DisplayName("with simple values gives expected result")
		void starMapTestSimpleValues() {
			// Small ZpGroup.
			final ZqGroup group = new ZqGroup(ELEVEN);

			// Construct the two vectors and value y.
			final GroupVector<ZqElement, ZqGroup> firstVector = GroupVector.of(
					ZqElement.create(TWO, group), ZqElement.create(SIX, group));
			final GroupVector<ZqElement, ZqGroup> secondVector = GroupVector.of(
					ZqElement.create(THREE, group), ZqElement.create(SEVEN, group));
			final ZqElement y = ZqElement.create(EIGHT, group);

			// Expected starMap result.
			final ZqElement expected = ZqElement.create(EIGHT, group);

			assertEquals(expected, zeroArgumentService.starMap(firstVector, secondVector, y));
		}

		@ParameterizedTest
		@MethodSource("starMapRealValuesProvider")
		@DisplayName("with real values gives expected result")
		void starMapRealValues(final GroupVector<ZqElement, ZqGroup> firstVector, final GroupVector<ZqElement, ZqGroup> secondVector,
				final ZqElement y, final ZqElement expectedOutput, final String description) {

			final ZqElement actualOutput = zeroArgumentService.starMap(firstVector, secondVector, y);

			assertEquals(actualOutput, expectedOutput, String.format("assertion failed for: %s", description));
		}

		Stream<Arguments> starMapRealValuesProvider() {
			final List<TestParameters> parametersList = TestParameters.fromResource("/mixnet/bilinearMap.json");

			return parametersList.stream().parallel().map(testParameters -> {
				// Context.
				final JsonData context = testParameters.getContext();
				final BigInteger q = context.get("q", BigInteger.class);

				final ZqGroup zqGroup = new ZqGroup(q);

				// Inputs.
				final JsonData input = testParameters.getInput();

				final BigInteger[] aVector = input.get("a", BigInteger[].class);
				final GroupVector<ZqElement, ZqGroup> firstVector = Arrays.stream(aVector)
						.map(bi -> ZqElement.create(bi, zqGroup))
						.collect(toGroupVector());

				final BigInteger[] bVector = input.get("b", BigInteger[].class);
				final GroupVector<ZqElement, ZqGroup> secondVector = Arrays.stream(bVector)
						.map(bi -> ZqElement.create(bi, zqGroup))
						.collect(toGroupVector());

				final BigInteger yValue = input.get("y", BigInteger.class);
				final ZqElement y = ZqElement.create(yValue, zqGroup);

				// Output.
				final JsonData output = testParameters.getOutput();
				final BigInteger outputValue = output.get("value", BigInteger.class);
				final ZqElement expectedOutput = ZqElement.create(outputValue, zqGroup);

				return Arguments.of(firstVector, secondVector, y, expectedOutput, testParameters.getDescription());
			});
		}
	}

	@Nested
	@DisplayName("getZeroArgument")
	class GetZeroArgument {

		private int m;
		private int n;
		private ZeroStatement zeroStatement;
		private ZeroWitness zeroWitness;

		@BeforeEach
		void setUp() {
			final ZeroArgumentService zeroArgumentService = new ZeroArgumentService(publicKey, commitmentKey, randomService, hashService);
			final ZeroArgumentTestData testData = new ZeroArgumentTestData(commitmentKey, zeroArgumentService);
			zeroStatement = testData.getZeroStatement();
			zeroWitness = testData.getZeroWitness();
			m = testData.getM();
			n = testData.getN();
		}

		@Test
		@DisplayName("with valid statement and witness does not throw")
		void getZeroArgValidStatementAndWitness() {
			final ZeroArgumentService zeroArgumentService = new ZeroArgumentService(publicKey, commitmentKey, randomService, hashService);
			final ZeroArgumentTestData testData = new ZeroArgumentTestData(commitmentKey, zeroArgumentService);
			final ZeroStatement zeroStatement = testData.getZeroStatement();
			final ZeroWitness zeroWitness = testData.getZeroWitness();

			final ZeroArgumentService otherZeroArgumentService = testData.getZeroArgumentService();

			assertDoesNotThrow(() -> otherZeroArgumentService.getZeroArgument(zeroStatement, zeroWitness));
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void getZeroArgNullParams() {
			assertThrows(NullPointerException.class, () -> zeroArgumentService.getZeroArgument(null, zeroWitness));
			assertThrows(NullPointerException.class, () -> zeroArgumentService.getZeroArgument(zeroStatement, null));
		}

		@Test
		@DisplayName("with commitments and exponents of different size throws IllegalArgumentException ")
		void getZeroArgDiffComExp() {
			// Create another witness with an additional element.
			final GroupMatrix<ZqElement, ZqGroup> matrixA = zqGroupGenerator.genRandomZqElementMatrix(n, m + 1);
			final GroupMatrix<ZqElement, ZqGroup> matrixB = zqGroupGenerator.genRandomZqElementMatrix(n, m + 1);
			final GroupVector<ZqElement, ZqGroup> exponentsR = zqGroupGenerator.genRandomZqElementVector(m + 1);
			final GroupVector<ZqElement, ZqGroup> exponentsS = zqGroupGenerator.genRandomZqElementVector(m + 1);

			final ZeroWitness addElemZeroWitness = new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(zeroStatement, addElemZeroWitness));
			assertEquals("The statement and witness must have the same dimension m.", exception.getMessage());
		}

		@Test
		@DisplayName("with y and exponents of different group throws IllegalArgumentException")
		void getZeroArgDiffGroupYAndExponents() {
			// Create another witness in another group.
			final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(GroupTestData.getDifferentZqGroup(zqGroup));
			final GroupMatrix<ZqElement, ZqGroup> matrixA = otherZqGroupGenerator.genRandomZqElementMatrix(n, m);
			final GroupMatrix<ZqElement, ZqGroup> matrixB = otherZqGroupGenerator.genRandomZqElementMatrix(n, m);
			final GroupVector<ZqElement, ZqGroup> exponentsR = otherZqGroupGenerator.genRandomZqElementVector(m);
			final GroupVector<ZqElement, ZqGroup> exponentsS = otherZqGroupGenerator.genRandomZqElementVector(m);

			final ZeroWitness otherZqGroupZeroWitness = new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(zeroStatement, otherZqGroupZeroWitness));
			assertEquals("The statement and witness must have compatible groups.", exception.getMessage());

		}

		@Test
		@DisplayName("with Ca commitments not equal to commitment matrix of A throws IllegalArgumentException")
		void getZeroArgDiffCaCommitments() {
			final GroupVector<GqElement, GqGroup> commitmentsA = zeroStatement.get_c_A();

			// Generate a different commitment.
			final GroupVector<GqElement, GqGroup> otherCommitments = Generators
					.genWhile(() -> gqGroupGenerator.genRandomGqElementVector(m), commitments -> commitments.equals(commitmentsA));

			final GroupVector<GqElement, GqGroup> commitmentsB = zeroStatement.get_c_B();
			final ZeroStatement otherStatement = new ZeroStatement(otherCommitments, commitmentsB, zeroStatement.get_y());

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(otherStatement, zeroWitness));
			assertEquals("The statement's Ca commitments must be equal to the witness' commitment matrix A.", exception.getMessage());
		}

		@Test
		@DisplayName("with Cb commitments not equal to commitment matrix of B throws IllegalArgumentException")
		void getZeroArgDiffCbCommitments() {
			final GroupVector<GqElement, GqGroup> commitmentsB = zeroStatement.get_c_B();

			// Generate a different commitment.
			final GroupVector<GqElement, GqGroup> otherCommitments = Generators
					.genWhile(() -> gqGroupGenerator.genRandomGqElementVector(m), commitments -> commitments.equals(commitmentsB));

			final GroupVector<GqElement, GqGroup> commitmentsA = zeroStatement.get_c_A();
			final ZeroStatement otherStatement = new ZeroStatement(commitmentsA, otherCommitments, zeroStatement.get_y());

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(otherStatement, zeroWitness));
			assertEquals("The statement's Cb commitments must be equal to the witness' commitment matrix B.", exception.getMessage());
		}

		@Test
		@DisplayName("with starMap sum not equal to 0 throws IllegalArgumentException")
		void getZeroArgStarMapNotZero() {
			// Create a simple witness.
			final GroupMatrix<ZqElement, ZqGroup> matrixA = GroupMatrix
					.fromRows(Collections.singletonList(Collections.singletonList(ZqElement.create(ONE, zqGroup))));
			final GroupMatrix<ZqElement, ZqGroup> matrixB = GroupMatrix
					.fromRows(Collections.singletonList(Collections.singletonList(ZqElement.create(ONE, zqGroup))));
			final GroupVector<ZqElement, ZqGroup> exponentsR = GroupVector.of(ZqElement.create(ONE, zqGroup));
			final GroupVector<ZqElement, ZqGroup> exponentsS = GroupVector.of(ZqElement.create(ONE, zqGroup));
			final ZeroWitness otherWitness = new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS);

			// Derive statement from it.
			final GroupVector<GqElement, GqGroup> commitmentsA = CommitmentService
					.getCommitmentMatrix(matrixA, exponentsR, commitmentKey);
			final GroupVector<GqElement, GqGroup> commitmentsB = CommitmentService
					.getCommitmentMatrix(matrixB, exponentsS, commitmentKey);
			// Fix y to 1 so the starMap gives 1 (because A and B are 1).
			final ZqElement y = ZqElement.create(ONE, zqGroup);
			final ZeroStatement otherStatement = new ZeroStatement(commitmentsA, commitmentsB, y);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.getZeroArgument(otherStatement, otherWitness));
			assertEquals("The sum of the starMap operations between the witness's matrices columns is not equal to 0.", exception.getMessage());
		}

		@Test
		@DisplayName("with simple values gives expected result")
		void getZeroArgSimpleValues() {
			// Groups.
			final GqGroup simpleGqGroup = new GqGroup(ELEVEN, FIVE, THREE);
			final ZqGroup simpleZqGroup = ZqGroup.sameOrderAs(simpleGqGroup);

			// Statement.
			final GroupVector<GqElement, GqGroup> commitmentsA = GroupVector.of(
					GqElementFactory.fromValue(FIVE, simpleGqGroup), GqElementFactory.fromValue(THREE, simpleGqGroup),
					GqElementFactory.fromValue(FOUR, simpleGqGroup));
			final GroupVector<GqElement, GqGroup> commitmentsB = GroupVector.of(
					GqElementFactory.fromValue(FOUR, simpleGqGroup), GqElementFactory.fromValue(NINE, simpleGqGroup),
					GqElementFactory.fromValue(NINE, simpleGqGroup));
			final ZqElement y = ZqElement.create(TWO, simpleZqGroup);

			final ZeroStatement simpleZeroStatement = new ZeroStatement(commitmentsA, commitmentsB, y);

			// Witness.
			final GroupMatrix<ZqElement, ZqGroup> simpleMatrixA = GroupMatrix.fromRows(asList(
					asList(ZqElement.create(TWO, simpleZqGroup), ZqElement.create(ZERO, simpleZqGroup), ZqElement.create(FOUR, simpleZqGroup)),
					asList(ZqElement.create(TWO, simpleZqGroup), ZqElement.create(FOUR, simpleZqGroup), ZqElement.create(FOUR, simpleZqGroup))));
			final GroupMatrix<ZqElement, ZqGroup> simpleMatrixB = GroupMatrix.fromRows(asList(
					asList(ZqElement.create(THREE, simpleZqGroup), ZqElement.create(TWO, simpleZqGroup), ZqElement.create(ONE, simpleZqGroup)),
					asList(ZqElement.create(ZERO, simpleZqGroup), ZqElement.create(ZERO, simpleZqGroup), ZqElement.create(ZERO, simpleZqGroup))));
			final GroupVector<ZqElement, ZqGroup> simpleExponentsR = GroupVector.of(
					ZqElement.create(THREE, simpleZqGroup), ZqElement.create(FOUR, simpleZqGroup), ZqElement.create(ZERO, simpleZqGroup));
			final GroupVector<ZqElement, ZqGroup> simpleExponentsS = GroupVector.of(
					ZqElement.create(ONE, simpleZqGroup), ZqElement.create(TWO, simpleZqGroup), ZqElement.create(FOUR, simpleZqGroup));

			final ZeroWitness simpleZeroWitness = new ZeroWitness(simpleMatrixA, simpleMatrixB, simpleExponentsR, simpleExponentsS);

			// Argument.
			final GqElement cA0 = GqElementFactory.fromValue(FIVE, simpleGqGroup);
			final GqElement cBm = GqElementFactory.fromValue(ONE, simpleGqGroup);
			final GroupVector<GqElement, GqGroup> cd = GroupVector.of(
					GqElementFactory.fromValue(FOUR, simpleGqGroup), GqElementFactory.fromValue(FOUR, simpleGqGroup),
					GqElementFactory.fromValue(NINE, simpleGqGroup),
					GqElementFactory.fromValue(NINE, simpleGqGroup), GqElementFactory.fromValue(ONE, simpleGqGroup),
					GqElementFactory.fromValue(THREE, simpleGqGroup),
					GqElementFactory.fromValue(ONE, simpleGqGroup));
			final GroupVector<ZqElement, ZqGroup> aPrime = GroupVector.of(
					ZqElement.create(TWO, simpleZqGroup), ZqElement.create(ZERO, simpleZqGroup));
			final GroupVector<ZqElement, ZqGroup> bPrime = GroupVector.of(
					ZqElement.create(ONE, simpleZqGroup), ZqElement.create(ONE, simpleZqGroup));
			final ZqElement rPrime = ZqElement.create(ONE, simpleZqGroup);
			final ZqElement sPrime = ZqElement.create(FOUR, simpleZqGroup);
			final ZqElement tPrime = ZqElement.create(ONE, simpleZqGroup);

			final ZeroArgument.Builder zeroArgumentBuilder = new ZeroArgument.Builder();
			zeroArgumentBuilder
					.with_c_A_0(cA0)
					.with_c_B_m(cBm)
					.with_c_d(cd)
					.with_a_prime(aPrime)
					.with_b_prime(bPrime)
					.with_r_prime(rPrime)
					.with_s_prime(sPrime)
					.with_t_prime(tPrime);
			final ZeroArgument simpleZeroArgument = zeroArgumentBuilder.build();

			// PublicKey and commitmentKey.
			final GqElement h = GqElementFactory.fromValue(NINE, simpleGqGroup);
			final List<GqElement> g = asList(GqElementFactory.fromValue(FOUR, simpleGqGroup), GqElementFactory.fromValue(NINE, simpleGqGroup));
			final CommitmentKey simpleCommitmentKey = new CommitmentKey(h, g);

			final List<GqElement> pkElements = asList(GqElementFactory.fromValue(FOUR, simpleGqGroup),
					GqElementFactory.fromValue(FOUR, simpleGqGroup));
			final ElGamalMultiRecipientPublicKey simplePublicKey = new ElGamalMultiRecipientPublicKey(pkElements);

			// Mock random elements. There are 13 values to mock:
			// a0=(1,3) bm=(2,1) r0=4 sm=0 t=(0,1,3,4,2,1,2)
			final RandomService randomServiceMock = spy(randomService);
			doReturn(ONE, THREE, TWO, ONE, FOUR, ZERO, ZERO, ONE, THREE, FOUR, TWO, ONE, TWO).when(randomServiceMock)
					.genRandomInteger(simpleZqGroup.getQ());

			// Mock the hashService.
			final HashService hashService = TestHashService.create(simpleGqGroup.getQ());

			final ZeroArgumentService simpleZeroArgumentService = new ZeroArgumentService(simplePublicKey, simpleCommitmentKey, randomServiceMock,
					hashService);

			// Verification.
			final ZeroArgument zeroArgument = simpleZeroArgumentService.getZeroArgument(simpleZeroStatement, simpleZeroWitness);
			verify(randomServiceMock, times(13)).genRandomInteger(simpleZqGroup.getQ());

			assertEquals(simpleZeroArgument, zeroArgument);
		}
	}

	@Nested
	@DisplayName("VerifyZeroArgument")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VerifyZeroArgument {

		@RepeatedTest(10)
		void verifyZeroArgumentTest() {
			final ZeroArgumentService zeroArgumentService = new ZeroArgumentService(publicKey, commitmentKey, randomService, hashService);
			final ZeroArgumentTestData testData = new ZeroArgumentTestData(commitmentKey, zeroArgumentService);
			final ZeroArgumentService verifyZeroArgumentService = testData.getZeroArgumentService();
			final ZeroStatement statement = testData.getZeroStatement();
			final ZeroWitness witness = testData.getZeroWitness();

			final ZeroArgument zeroArgument = verifyZeroArgumentService.getZeroArgument(statement, witness);

			assertTrue(verifyZeroArgumentService.verifyZeroArgument(statement, zeroArgument).verify().isVerified());
		}

		@Test
		void testNullInputParameters() {
			final ZeroArgument zeroArgument = mock(ZeroArgument.class);
			final ZeroStatement zeroStatement = mock(ZeroStatement.class);

			assertThrows(NullPointerException.class, () -> zeroArgumentService.verifyZeroArgument(zeroStatement, null));
			assertThrows(NullPointerException.class, () -> zeroArgumentService.verifyZeroArgument(null, zeroArgument));
		}

		@Test
		void testInputParameterGroupSizes() {
			final ZeroArgument zeroArgument = mock(ZeroArgument.class, Mockito.RETURNS_DEEP_STUBS);
			final ZeroStatement zeroStatement = mock(ZeroStatement.class, Mockito.RETURNS_DEEP_STUBS);

			when(zeroArgument.getGroup()).thenReturn(gqGroup);
			when(zeroStatement.getGroup()).thenReturn(gqGroup);

			when(zeroArgument.get_m()).thenReturn(1);
			when(zeroStatement.get_m()).thenReturn(2);

			final IllegalArgumentException invalidMException = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.verifyZeroArgument(zeroStatement, zeroArgument));
			assertEquals("The statement and argument must have the same dimension m.", invalidMException.getMessage());

		}

		@Test
		void testInputParameterGroupMembership() {
			final ZeroArgument zeroArgument = mock(ZeroArgument.class, Mockito.RETURNS_DEEP_STUBS);
			final ZeroStatement otherGroupStatement = mock(ZeroStatement.class, Mockito.RETURNS_DEEP_STUBS);

			when(zeroArgument.get_c_d().getGroup()).thenReturn(gqGroup);
			when(otherGroupStatement.get_c_A().getGroup()).thenReturn(GroupTestData.getDifferentGqGroup(gqGroup));

			final IllegalArgumentException wrongGroupException = assertThrows(IllegalArgumentException.class,
					() -> zeroArgumentService.verifyZeroArgument(otherGroupStatement, zeroArgument));
			assertEquals("Statement and argument must belong to the same group.", wrongGroupException.getMessage());

		}

		@ParameterizedTest
		@MethodSource("verifyZeroArgumentRealValuesProvider")
		@DisplayName("with real values gives expected result")
		void verifyZeroArgumentRealValues(final ElGamalMultiRecipientPublicKey publicKey, final CommitmentKey commitmentKey,
				final ZeroStatement zeroStatement, final ZeroArgument zeroArgument, final boolean expectedOutput, final String description) {

			final HashService hashService = HashService.getInstance();

			final ZeroArgumentService service = new ZeroArgumentService(publicKey, commitmentKey, randomService, hashService);

			assertEquals(expectedOutput, service.verifyZeroArgument(zeroStatement, zeroArgument).verify().isVerified(),
					String.format("assertion failed for: %s", description));
		}

		Stream<Arguments> verifyZeroArgumentRealValuesProvider() {
			final List<TestParameters> parametersList = TestParameters.fromResource("/mixnet/verify-zero-argument.json");

			return parametersList.stream().parallel().map(testParameters -> {
				// Context.
				final JsonData contextData = testParameters.getContext();
				final TestContextParser context = new TestContextParser(contextData);
				final GqGroup realGqGroup = context.getGqGroup();

				final ElGamalMultiRecipientPublicKey publicKey = context.parsePublicKey();
				final CommitmentKey commitmentKey = context.parseCommitmentKey();

				// Inputs.
				final JsonData input = testParameters.getInput();
				final ZeroStatement zeroStatement = parseZeroStatement(realGqGroup, input);
				final ZeroArgument zeroArgument = new TestArgumentParser(realGqGroup).parseZeroArgument(input.getJsonData("argument"));

				// Output.
				final JsonData output = testParameters.getOutput();
				final boolean outputValue = Boolean.parseBoolean(output.toString());

				return Arguments.of(publicKey, commitmentKey, zeroStatement, zeroArgument, outputValue, testParameters.getDescription());
			});
		}

		private ZeroStatement parseZeroStatement(final GqGroup realGqGroup, final JsonData input) {
			final JsonData zeroStatementJsonData = input.getJsonData("statement");

			final GroupVector<GqElement, GqGroup> cA = parseCommitment(zeroStatementJsonData, "c_a", realGqGroup);
			final GroupVector<GqElement, GqGroup> cB = parseCommitment(zeroStatementJsonData, "c_b", realGqGroup);

			final BigInteger yValue = zeroStatementJsonData.get("y", BigInteger.class);
			final ZqElement y = ZqElement.create(yValue, ZqGroup.sameOrderAs(realGqGroup));

			return new ZeroStatement(cA, cB, y);
		}
	}
}
