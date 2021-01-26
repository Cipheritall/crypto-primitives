/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.BigIntegerOperations;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class CommitmentServiceTest {

	private static final int KEY_LENGTH = 5; // This must be >= 2
	private static final RandomService randomService = new RandomService();
	private static final SecureRandom secureRandom = new SecureRandom();
	private final CommitmentService commitmentService = new CommitmentService();
	private GqGroup gqGroup;
	private ZqGroup zqGroup;
	private CommitmentKey validCommitmentKey;

	@BeforeEach
	void setup() {
		gqGroup = GqGroupTestData.getGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		validCommitmentKey = genCommitmentKey(gqGroup, KEY_LENGTH);
	}

	@Nested
	@DisplayName("getCommitment")
	class GetCommitmentTest {

		private List<ZqElement> validElements;
		private ZqElement randomValue;

		@BeforeEach
		void setup() {
			validElements = Stream.generate(() -> ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup)).limit(KEY_LENGTH).collect(Collectors.toList());
			randomValue = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void getCommitmentWithNullParameters() {
			assertThrows(NullPointerException.class, () -> commitmentService.getCommitment(null, randomValue, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> commitmentService.getCommitment(validElements, null, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> commitmentService.getCommitment(validElements, randomValue, null));
		}

		@Test
		@DisplayName("with empty list of values to commit to does not throw")
		void getCommitmentOfEmptyList() {
			List<ZqElement> values = Collections.emptyList();
			assertNotNull(commitmentService.getCommitment(values, randomValue, validCommitmentKey));
		}

		@RepeatedTest(10)
		@DisplayName("with empty list result is multimodexp with padding")
		void withEmptyListResultIsMultiModExpWithPadding() {
			List<ZqElement> values = Collections.emptyList();
			List<BigInteger> aPrime = Stream.generate(() -> BigInteger.ZERO).limit(KEY_LENGTH).collect(Collectors.toList());
			aPrime.add(0, randomValue.getValue());
			BigInteger expected = BigIntegerOperations.multiModExp(
					Stream.concat(Stream.of(validCommitmentKey.getH()), validCommitmentKey.stream()).map(GqElement::getValue).collect(Collectors.toList()),
					aPrime,
					gqGroup.getP());
			assertEquals(expected, commitmentService.getCommitment(values, randomValue, validCommitmentKey).getValue());
		}

		@Test
		@DisplayName("with element list longer than commitment key throws IllegalArgumentException")
		void getCommitmentWithTooLongListOfValues() {
			List<ZqElement> tooLongList = new ArrayList<>(validElements);
			tooLongList.add(zqGroup.getIdentity());
			assertThrows(IllegalArgumentException.class, () -> commitmentService.getCommitment(tooLongList, randomValue, validCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and commitment key in groups of different order throws IllegalArgumentException")
		void getCommitmentWithCommitmentKeyGroupDifferentOrderThanValuesGroup() {
			GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			CommitmentKey differentCommitmentKey = genCommitmentKey(differentGqGroup, KEY_LENGTH);
			assertThrows(IllegalArgumentException.class, () -> commitmentService.getCommitment(validElements, randomValue, differentCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and random element from different groups throws IllegalArgumentException")
		void getCommitmentWithRandomValueDifferentGroupThanValues() {
			ZqGroup differentZqGroup = new ZqGroup(zqGroup.getQ().multiply(BigInteger.TEN));
			ZqElement differentRandomValue = ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup);
			assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitment(validElements, differentRandomValue, validCommitmentKey));

		}

		@Test
		@DisplayName("with elements of different groups to be committed to throws IllegalArgumentException")
		void getCommitmentWithElementsFromDifferentGroups() {
			List<ZqElement> invalidElements = new ArrayList<>(validElements);
			ZqGroup differentZqGroup = getDifferentZqGroup();
			invalidElements.set(0, differentZqGroup.getIdentity());
			assertThrows(IllegalArgumentException.class, () -> commitmentService.getCommitment(invalidElements, randomValue, validCommitmentKey));
		}

		@RepeatedTest(100)
		@DisplayName("returns a commitment that belongs to the same group than the commitment key elements")
		void getCommitmentInSameGroupAsCommitmentKey() {
			assertEquals(gqGroup, commitmentService.getCommitment(validElements, randomValue, validCommitmentKey).getGroup());
		}

		@RepeatedTest(100)
		@DisplayName("returns the same commitment when elements are added to the commitment key")
		void getCommitmentWithLongerCommitmentKeyYieldsSameResult() {
			CommitmentKey longerCommitmentKey = genCommitmentKey(gqGroup, 2 * KEY_LENGTH);
			CommitmentKey exactCommitmentKey =
					new CommitmentKey(longerCommitmentKey.getH(), longerCommitmentKey.stream().limit(KEY_LENGTH).collect(Collectors.toList()));
			GqElement commitmentExactCK = commitmentService.getCommitment(validElements, randomValue, exactCommitmentKey);
			GqElement commitmentLongerCK = commitmentService.getCommitment(validElements, randomValue, longerCommitmentKey);
			assertEquals(commitmentExactCK, commitmentLongerCK);
		}

		@Test
		@DisplayName("with simple values returns expected result")
		void getCommitmentWithSpecificValues() {
			GqGroup specificGqGroup = new GqGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(6));
			ZqGroup specificZqGroup = ZqGroup.sameOrderAs(specificGqGroup);
			// a = (2, 10)
			List<ZqElement> a = new ArrayList<>();
			a.add(ZqElement.create(BigInteger.valueOf(2), specificZqGroup));
			a.add(ZqElement.create(BigInteger.valueOf(10), specificZqGroup));
			// r = 5
			ZqElement r = ZqElement.create(BigInteger.valueOf(5), specificZqGroup);
			// ck = (2, 3, 4)
			List<GqElement> gElements = new ArrayList<>(2);
			GqElement h = GqElement.create(BigInteger.valueOf(2), specificGqGroup);
			gElements.add(GqElement.create(BigInteger.valueOf(3), specificGqGroup));
			gElements.add(GqElement.create(BigInteger.valueOf(4), specificGqGroup));
			CommitmentKey ck = new CommitmentKey(h, gElements);
			// c = 3
			GqElement expected = GqElement.create(BigInteger.valueOf(3), specificGqGroup);

			assertEquals(expected, commitmentService.getCommitment(a, r, ck));
		}
	}

	@Nested
	@DisplayName("getCommitmentMatrix")
	class GetCommitmentMatrixTest {

		private int m;
		private int n;

		private SameGroupMatrix<ZqElement, ZqGroup> validMatrix;
		private SameGroupVector<ZqElement, ZqGroup> validRandomValues;

		@BeforeEach
		void setup() {
			m = secureRandom.nextInt(10) + 1;
			n = KEY_LENGTH;
			validMatrix = SameGroupMatrix.fromRows(generateRandomZqElementMatrix(n, m, zqGroup));
			validRandomValues = new SameGroupVector<>(generateRandomZqElementList(m, zqGroup));
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void getCommitmentMatrixWithNullParameters() {
			assertThrows(NullPointerException.class, () -> commitmentService.getCommitmentMatrix(null, validRandomValues, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> commitmentService.getCommitmentMatrix(validMatrix, null, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> commitmentService.getCommitmentMatrix(validMatrix, validRandomValues, null));
		}

		@Test
		@DisplayName("with empty elements matrix returns empty list")
		void getCommitmentMatrixWithEmptyElementsMatrix() {
			SameGroupMatrix<ZqElement, ZqGroup> emptyMatrix = SameGroupMatrix.fromRows(generateRandomZqElementMatrix(0, 0, zqGroup));

			assertEquals(Collections.emptyList(),
					commitmentService.getCommitmentMatrix(emptyMatrix, validRandomValues, validCommitmentKey));
		}

		@Test
		@DisplayName("with empty rows in elements matrix returns empty list")
		void getCommitmentMatrixWithEmptyRowsInElementsMatrix() {
			SameGroupMatrix<ZqElement, ZqGroup> emptyRowsMatrix = SameGroupMatrix.fromRows(generateRandomZqElementMatrix(0, m, zqGroup));
			SameGroupVector<ZqElement, ZqGroup> emptyRandomElements = new SameGroupVector<>(generateRandomZqElementList(0, zqGroup));
			assertEquals(Collections.emptyList(), commitmentService.getCommitmentMatrix(emptyRowsMatrix, emptyRandomElements, validCommitmentKey));
		}

		@Test
		@DisplayName("with too large matrix throws IllegalArgumentException")
		void getCommitmentMatrixWithTooManyRows() {
			SameGroupMatrix<ZqElement, ZqGroup> tooManyRowsMatrix = SameGroupMatrix.fromRows(generateRandomZqElementMatrix(n+1, m, zqGroup));

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(tooManyRowsMatrix, validRandomValues, validCommitmentKey));
			assertEquals("The commitment key must be longer than the number of rows of the elements matrix", exception.getMessage());
		}

		@Test
		@DisplayName("with matrix group and commitment key group different order throws IllegalArgumentException")
		void getCommitmentMatrixWithCommitmentKeyGroupDifferentOrderThanValuesGroup() {
			GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			CommitmentKey differentCommitmentKey = genCommitmentKey(differentGqGroup, n);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(validMatrix, validRandomValues, differentCommitmentKey));
			assertEquals("The commitment key must have the same order (q) than the elements to be committed to and the random values", exception.getMessage());
		}

		@Test
		@DisplayName("with matrix group different from random values group throws IllegalArgumentException")
		void getCommitmentWithRandomValueDifferentGroupThanValues() {
			ZqGroup differentZqGroup = new ZqGroup(zqGroup.getQ().multiply(BigInteger.TEN));
			SameGroupVector<ZqElement, ZqGroup> differentRandomValues = new SameGroupVector<>(generateRandomZqElementList(m, differentZqGroup));

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(validMatrix, differentRandomValues, validCommitmentKey));
			assertEquals("The elements to be committed to and the random elements must be in the same group.", exception.getMessage());
		}

		@RepeatedTest(100)
		@DisplayName("returns commitment vector of the same group than the commitment key")
		void getCommitmentMatrixInSameGroupAsCommitmentKey() {
			List<GqElement> commitment = commitmentService.getCommitmentMatrix(validMatrix, validRandomValues, validCommitmentKey);
			GqGroup commitmentGroup = commitment.get(0).getGroup();
			assertEquals(gqGroup, commitmentGroup);
		}

		@RepeatedTest(100)
		@DisplayName("returns the same commitment when elements are added to the commitment key")
		void getCommitmentMatrixWithLongerCommitmentKeyYieldsSameResult() {
			CommitmentKey longerCommitmentKey = genCommitmentKey(gqGroup, 2 * n);
			CommitmentKey exactCommitmentKey =
					new CommitmentKey(longerCommitmentKey.getH(), longerCommitmentKey.stream().limit(n).collect(Collectors.toList()));
			List<GqElement> commitmentExactCK = commitmentService.getCommitmentMatrix(validMatrix, validRandomValues, exactCommitmentKey);
			List<GqElement> commitmentLongerCK = commitmentService.getCommitmentMatrix(validMatrix, validRandomValues, longerCommitmentKey);
			assertEquals(commitmentExactCK, commitmentLongerCK);
		}

		@Test
		void getCommitmentMatrixWithSpecificValues() {
			GqGroup specificGqGroup = new GqGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(6));
			ZqGroup specificZqGroup = ZqGroup.sameOrderAs(specificGqGroup);
			// a0 = (2, 10)
			List<ZqElement> a0 = new ArrayList<>(2);
			a0.add(ZqElement.create(BigInteger.valueOf(2), specificZqGroup));
			a0.add(ZqElement.create(BigInteger.valueOf(10), specificZqGroup));
			// a1 = (3, 4)
			List<ZqElement> a1 = new ArrayList<>(2);
			a1.add(ZqElement.create(BigInteger.valueOf(8), specificZqGroup));
			a1.add(ZqElement.create(BigInteger.valueOf(9), specificZqGroup));
			// a = (a0, a1)
			SameGroupMatrix<ZqElement, ZqGroup> a = SameGroupMatrix.fromColumns(Arrays.asList(a0, a1));
			// r = (5, 8)
			List<ZqElement> rValues = new ArrayList<>(2);
			rValues.add(ZqElement.create(BigInteger.valueOf(5), specificZqGroup));
			rValues.add(ZqElement.create(BigInteger.valueOf(8), specificZqGroup));
			SameGroupVector<ZqElement, ZqGroup> r = new SameGroupVector<>(rValues);
			// ck = (2, 3, 4)
			List<GqElement> gElements = new ArrayList<>();
			GqElement h = GqElement.create(BigInteger.valueOf(2), specificGqGroup);
			gElements.add(GqElement.create(BigInteger.valueOf(3), specificGqGroup));
			gElements.add(GqElement.create(BigInteger.valueOf(4), specificGqGroup));
			CommitmentKey ck = new CommitmentKey(h, gElements);
			// c = (3, 4)
			List<GqElement> expected = new ArrayList<>(2);
			expected.add(GqElement.create(BigInteger.valueOf(3), specificGqGroup));
			expected.add(GqElement.create(BigInteger.valueOf(4), specificGqGroup));

			assertEquals(expected, commitmentService.getCommitmentMatrix(a, r, ck));
		}
	}

	@Nested
	@DisplayName("getCommitmentVector")
	class GetCommitmentVectorTest {

		private List<ZqElement> validElements;
		private List<ZqElement> validRandomElements;

		@BeforeEach
		void setup() {
			validElements = generateRandomZqElementList(KEY_LENGTH, zqGroup);
			validRandomElements = generateRandomZqElementList(KEY_LENGTH, zqGroup);
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void getCommitmentVectorWithNullParameters() {
			assertThrows(NullPointerException.class, () -> commitmentService.getCommitmentVector(null, validRandomElements, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> commitmentService.getCommitmentVector(validElements, null, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> commitmentService.getCommitmentVector(validElements, validRandomElements, null));
		}

		@Test
		@DisplayName("with element list longer than commitment key throws IllegalArgumentException")
		void getCommitmentVectorWithTooLongListOfValues() {
			List<ZqElement> tooLongList = new ArrayList<>(validElements);
			tooLongList.add(zqGroup.getIdentity());
			assertThrows(IllegalArgumentException.class, () -> commitmentService.getCommitmentVector(tooLongList, validRandomElements, validCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and commitment key in groups of different order throws IllegalArgumentException")
		void getCommitmentVectorWithCommitmentKeyGroupDifferentOrderThanValuesGroup() {
			GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			CommitmentKey differentCommitmentKey = genCommitmentKey(differentGqGroup, KEY_LENGTH);
			assertThrows(IllegalArgumentException.class, () -> commitmentService.getCommitmentVector(validElements, validRandomElements, differentCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and random elements from different groups throws IllegalArgumentException")
		void getCommitmentVectorWithRandomValueDifferentGroupThanValues() {
			ZqGroup differentZqGroup = getDifferentZqGroup();
			List<ZqElement> differentRandomElements = generateRandomZqElementList(KEY_LENGTH, differentZqGroup);
			assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentVector(validElements, differentRandomElements, validCommitmentKey));

		}

		@Test
		@DisplayName("with elements of different groups to be committed to throws IllegalArgumentException")
		void getCommitmentVectorWithElementsFromDifferentGroups() {
			List<ZqElement> invalidElements = new ArrayList<>(validElements);
			ZqGroup differentZqGroup = getDifferentZqGroup();
			invalidElements.set(0, differentZqGroup.getIdentity());
			assertThrows(IllegalArgumentException.class, () -> commitmentService.getCommitmentVector(invalidElements, validRandomElements, validCommitmentKey));
		}

		@Test
		@DisplayName("with random values of different groups throws IllegalArgumentException")
		void getCommitmentVectorWithRandomValuesFromDifferentGroups() {
			List<ZqElement> validElements = generateRandomZqElementList(KEY_LENGTH+1, zqGroup);
			List<ZqElement> invalidRandomValues = generateRandomZqElementList(KEY_LENGTH+1, zqGroup);
			ZqGroup differentZqGroup = getDifferentZqGroup();
			invalidRandomValues.set(KEY_LENGTH, differentZqGroup.getIdentity());
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentVector(validElements, invalidRandomValues, validCommitmentKey));
			assertEquals("All elements must belong to the same group.", exception.getMessage());
		}

		@RepeatedTest(100)
		@DisplayName("returns a commitment that belongs to the same group than the commitment key elements")
		void getCommitmentVectorInSameGroupAsCommitmentKey() {
			List<GqElement> commitment = commitmentService.getCommitmentVector(validElements, validRandomElements, validCommitmentKey);
			assertTrue(commitment.stream().map(GqElement::getGroup).allMatch(gqGroup::equals));
		}

		@RepeatedTest(100)
		@DisplayName("returns the same commitment when elements are added to the commitment key")
		void getCommitmentVectorWithLongerCommitmentKeyYieldsSameResult() {
			CommitmentKey longerCommitmentKey = genCommitmentKey(gqGroup, 2 * KEY_LENGTH);
			CommitmentKey exactCommitmentKey =
					new CommitmentKey(longerCommitmentKey.getH(), longerCommitmentKey.stream().limit(KEY_LENGTH).collect(Collectors.toList()));
			List<GqElement> commitmentExactCK = commitmentService.getCommitmentVector(validElements, validRandomElements, exactCommitmentKey);
			List<GqElement> commitmentLongerCK = commitmentService.getCommitmentVector(validElements, validRandomElements, longerCommitmentKey);
			assertEquals(commitmentExactCK, commitmentLongerCK);
		}

		@Test
		@DisplayName("with simple values returns expected result")
		void getCommitmentVectorWithSpecificValues() {
			GqGroup specificGqGroup = new GqGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(6));
			ZqGroup specificZqGroup = ZqGroup.sameOrderAs(specificGqGroup);
			// a = (2, 10)
			List<ZqElement> a = new ArrayList<>(2);
			a.add(ZqElement.create(BigInteger.valueOf(2), specificZqGroup));
			a.add(ZqElement.create(BigInteger.valueOf(10), specificZqGroup));
			// r = (5, 8)
			List<ZqElement> r = new ArrayList<>(2);
			r.add(ZqElement.create(BigInteger.valueOf(5), specificZqGroup));
			r.add(ZqElement.create(BigInteger.valueOf(8), specificZqGroup));
			// ck = (2, 3)
			List<GqElement> gElements = new ArrayList<>();
			GqElement h = GqElement.create(BigInteger.valueOf(2), specificGqGroup);
			gElements.add(GqElement.create(BigInteger.valueOf(3), specificGqGroup));
			CommitmentKey ck = new CommitmentKey(h, gElements);
			// c = (12, 1)
			List<GqElement> expected = new ArrayList<>(2);
			expected.add(GqElement.create(BigInteger.valueOf(12), specificGqGroup));
			expected.add(GqElement.create(BigInteger.valueOf(1), specificGqGroup));

			assertEquals(expected, commitmentService.getCommitmentVector(a, r, ck));
		}
	}

	// ===============================================================================================================================================
	// Utility methods
	// ===============================================================================================================================================

	/**
	 * Generate a random vector of {@link ZqElement} in the specified {@code group}.
	 *
	 * @param numElements the number of elements to generate.
	 * @return a vector of {@code numElements} random {@link ZqElement}.
	 */
	private List<ZqElement> generateRandomZqElementList(final int numElements, final ZqGroup group) {
		return Stream.generate(() -> ZqElement.create(randomService.genRandomInteger(group.getQ()), group)).limit(numElements)
				.collect(Collectors.toList());
	}

	/**
	 * Generate a random matrix of {@link ZqElement} in the specified {@code group}.
	 *
	 * @param m the matrix' number of lines.
	 * @param n the matrix' number of columns.
	 * @return a m &times; n matrix of random {@link ZqElement}.
	 */
	private List<List<ZqElement>> generateRandomZqElementMatrix(final int m, final int n, final ZqGroup group) {
		return Stream.generate(() -> generateRandomZqElementList(n, group)).limit(m).collect(Collectors.toList());
	}

	/**
	 * Generate a random commitment key in the given group and of given size.
	 *
	 * @param group	the {@link GqGroup} of the commitment key elements.
	 * @param k		the number of g elements of the key.
	 * @return		a new commitment key of length k + 1.
	 */
	private CommitmentKey genCommitmentKey(GqGroup group, int k) {
		GqGroupGenerator generator = new GqGroupGenerator(group);
		GqElement h = generator.genNonIdentityNonGeneratorMember();
		List<GqElement> gList = Stream.generate(generator::genNonIdentityNonGeneratorMember).limit(k).collect(Collectors.toList());
		return new CommitmentKey(h, gList);
	}

	/**
	 * Get a different ZqGroup from the one used before each test cases.
	 *
	 * @return a different {@link ZqGroup}.
	 */
	private ZqGroup getDifferentZqGroup() {
		GqGroup otherGqGroup;
		ZqGroup otherZqGroup;
		do {
			otherGqGroup = GqGroupTestData.getGroup();
			otherZqGroup = ZqGroup.sameOrderAs(otherGqGroup);
		} while (otherZqGroup.equals(zqGroup));

		return otherZqGroup;
	}
}
