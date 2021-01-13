/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.utils.GqGroupMemberGenerator;

class CommitmentServiceTest {

	private static final int NUM_ELEMENTS = 5; // This must be >= 2
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
		validCommitmentKey = genCommitmentKey(gqGroup, NUM_ELEMENTS);
	}

	@Nested
	@DisplayName("getCommitment")
	class GetCommitmentTest {

		private List<ZqElement> validElements;
		private ZqElement randomValue;

		@BeforeEach
		void setup() {
			validElements = Stream.generate(() -> ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup)).limit(NUM_ELEMENTS).collect(Collectors.toList());
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
			CommitmentKey differentCommitmentKey = genCommitmentKey(differentGqGroup, NUM_ELEMENTS);
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
			CommitmentKey longerCommitmentKey = genCommitmentKey(gqGroup, 2 * NUM_ELEMENTS);
			CommitmentKey exactCommitmentKey = new CommitmentKey(longerCommitmentKey.getH(), longerCommitmentKey.getGElements().subList(0, NUM_ELEMENTS));
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

		private List<List<ZqElement>> validMatrix;
		private List<ZqElement> validRandomValues;

		@BeforeEach
		void setup() {
			m = secureRandom.nextInt(10) + 1;
			n = NUM_ELEMENTS;
			validMatrix = generateRandomZqElementMatrix(m, n, zqGroup);
			validRandomValues = generateRandomZqElementList(m, zqGroup);
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void getCommitmentMatrixWithNullParameters() {
			assertThrows(NullPointerException.class, () -> commitmentService.getCommitmentMatrix(null, validRandomValues, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> commitmentService.getCommitmentMatrix(validMatrix, null, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> commitmentService.getCommitmentMatrix(validMatrix, validRandomValues, null));
		}

		@Test
		@DisplayName("with a null row in the element matrix throws IllegalArgumentException")
		void getCommitmentMatrixWithNullRowInElementMatrix() {
			List<List<ZqElement>> nullRowMatrix = generateRandomZqElementMatrix(m, n, zqGroup);
			nullRowMatrix.set(m-1, null);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(nullRowMatrix, validRandomValues, validCommitmentKey));
			assertEquals("Rows must not be null", exception.getMessage());
		}

		@Test
		@DisplayName("with a null element in the element matrix throws IllegalArgumentException")
		void getCommitmentMatrixWithNullElementInElementMatrix() {
			List<List<ZqElement>> nullElementMatrix = generateRandomZqElementMatrix(m, n, zqGroup);
			nullElementMatrix.get(m-1).set(0, null);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(nullElementMatrix, validRandomValues, validCommitmentKey));
			assertEquals("Elements must not be null", exception.getMessage());
		}

		@Test
		@DisplayName("with a null random element throws IllegalArgumentException")
		void getCommitmentMatrixWithNullRandomElement() {
			List<ZqElement> randomElementsWithNull = generateRandomZqElementList(m, zqGroup);
			randomElementsWithNull.set(m-1, null);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(validMatrix, randomElementsWithNull, validCommitmentKey));
			assertEquals("Random elements must not be null", exception.getMessage());
		}

		@Test
		@DisplayName("with empty elements matrix throws IllegalArgumentException")
		void getCommitmentMatrixWithEmptyElementsMatrix() {
			List<List<ZqElement>> emptyMatrix = generateRandomZqElementMatrix(0, 0, zqGroup);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(emptyMatrix, validRandomValues, validCommitmentKey));
			assertEquals("The elements matrix must have at least one row", exception.getMessage());
		}

		@Test
		@DisplayName("with empty rows in elements matrix throws IllegalArgumentException")
		void getCommitmentMatrixWithEmptyRowsInElementsMatrix() {
			List<List<ZqElement>> emptyRowsMatrix = generateRandomZqElementMatrix(m, 0, zqGroup);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(emptyRowsMatrix, validRandomValues, validCommitmentKey));
			assertEquals("The elements matrix must not have any empty rows", exception.getMessage());
		}

		@Test
		@DisplayName("with empty random element list throws IllegalArgumentException")
		void getCommitmentMatrixWithEmptyRandomElements() {
			List<ZqElement> emptyRandomElements = generateRandomZqElementList(0, zqGroup);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(validMatrix, emptyRandomElements, validCommitmentKey));
			assertEquals("There must be as many random elements as there are rows in the element matrix", exception.getMessage());
		}

		@Test
		@DisplayName("with too large matrix throws IllegalArgumentException")
		void getCommitmentMatrixWithTooManyColumns() {
			List<List<ZqElement>> tooManyColumnsMatrix = generateRandomZqElementMatrix(m, n+1, zqGroup);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(tooManyColumnsMatrix, validRandomValues, validCommitmentKey));
			assertEquals("The commitment key must be longer than the number of columns of the elements matrix", exception.getMessage());
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
			List<ZqElement> differentRandomValues = generateRandomZqElementList(m, differentZqGroup);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(validMatrix, differentRandomValues, validCommitmentKey));
			assertEquals("The elements to be committed to and the random elements must be in the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with elements of different groups to be committed to throws IllegalArgumentException")
		void getCommitmentWithElementsFromDifferentGroups() {
			List<List<ZqElement>> invalidMatrix = generateRandomZqElementMatrix(m, n, zqGroup);
			ZqGroup differentZqGroup = getDifferentZqGroup();
			invalidMatrix.get(0).set(0, differentZqGroup.getIdentity());
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(invalidMatrix, validRandomValues, validCommitmentKey));
			assertEquals("All elements to be committed must be in the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("with random values of different groups throws IllegalArgumentException")
		void getCommitmentMatrixWithRandomValuesFromDifferentGroups() {
			List<List<ZqElement>> validMatrix = generateRandomZqElementMatrix(m+1, n, zqGroup);
			List<ZqElement> invalidRandomValues = generateRandomZqElementList(m+1, zqGroup);
			ZqGroup differentZqGroup = getDifferentZqGroup();
			invalidRandomValues.set(m, differentZqGroup.getIdentity());
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentMatrix(validMatrix, invalidRandomValues, validCommitmentKey));
			assertEquals("All random elements must be in the same group.", exception.getMessage());
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
			CommitmentKey exactCommitmentKey = new CommitmentKey(longerCommitmentKey.getH(), longerCommitmentKey.getGElements().subList(0, n));
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
			List<List<ZqElement>> a = Arrays.asList(a0, a1);
			// r = (5, 8)
			List<ZqElement> r = new ArrayList<>(2);
			r.add(ZqElement.create(BigInteger.valueOf(5), specificZqGroup));
			r.add(ZqElement.create(BigInteger.valueOf(8), specificZqGroup));
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
			validElements = generateRandomZqElementList(NUM_ELEMENTS, zqGroup);
			validRandomElements = generateRandomZqElementList(NUM_ELEMENTS, zqGroup);
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
			CommitmentKey differentCommitmentKey = genCommitmentKey(differentGqGroup, NUM_ELEMENTS);
			assertThrows(IllegalArgumentException.class, () -> commitmentService.getCommitmentVector(validElements, validRandomElements, differentCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and random elements from different groups throws IllegalArgumentException")
		void getCommitmentVectorWithRandomValueDifferentGroupThanValues() {
			ZqGroup differentZqGroup = getDifferentZqGroup();
			List<ZqElement> differentRandomElements = generateRandomZqElementList(NUM_ELEMENTS, differentZqGroup);
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
			List<ZqElement> validElements = generateRandomZqElementList(NUM_ELEMENTS+1, zqGroup);
			List<ZqElement> invalidRandomValues = generateRandomZqElementList(NUM_ELEMENTS+1, zqGroup);
			ZqGroup differentZqGroup = getDifferentZqGroup();
			invalidRandomValues.set(NUM_ELEMENTS, differentZqGroup.getIdentity());
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> commitmentService.getCommitmentVector(validElements, invalidRandomValues, validCommitmentKey));
			assertEquals("All random elements must be in the same group.", exception.getMessage());
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
			CommitmentKey longerCommitmentKey = genCommitmentKey(gqGroup, 2 * NUM_ELEMENTS);
			CommitmentKey exactCommitmentKey = new CommitmentKey(longerCommitmentKey.getH(), longerCommitmentKey.getGElements().subList(0, NUM_ELEMENTS));
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
		GqGroupMemberGenerator generator = new GqGroupMemberGenerator(group);
		GqElement h = generator.genValidPublicKeyGqElementMember();
		List<GqElement> gList = Stream.generate(generator::genValidPublicKeyGqElementMember).limit(k).collect(Collectors.toList());
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
