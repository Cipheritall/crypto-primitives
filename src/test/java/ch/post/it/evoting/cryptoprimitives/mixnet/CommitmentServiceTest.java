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
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class CommitmentServiceTest {

	private static final int KEY_LENGTH = 5; // This must be >= 2
	private static final RandomService randomService = new RandomService();
	private static final SecureRandom secureRandom = new SecureRandom();

	private static ZqGroupGenerator zqGroupGenerator;

	private GqGroup gqGroup;
	private ZqGroup zqGroup;
	private CommitmentKey validCommitmentKey;

	@BeforeEach
	void setup() {
		gqGroup = GqGroupTestData.getGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		zqGroupGenerator = new ZqGroupGenerator(zqGroup);
		validCommitmentKey = genCommitmentKey(gqGroup, KEY_LENGTH);
	}

	/**
	 * Generate a random commitment key in the given group and of given size.
	 *
	 * @param group the {@link GqGroup} of the commitment key elements.
	 * @param k     the number of g elements of the key.
	 * @return a new commitment key of length k + 1.
	 */
	private CommitmentKey genCommitmentKey(GqGroup group, int k) {
		GqGroupGenerator generator = new GqGroupGenerator(group);
		GqElement h = generator.genNonIdentityNonGeneratorMember();
		List<GqElement> gList = Stream.generate(generator::genNonIdentityNonGeneratorMember).limit(k).collect(Collectors.toList());
		return new CommitmentKey(h, gList);
	}

	@Nested
	@DisplayName("getCommitment")
	class GetCommitmentTest {

		private SameGroupVector<ZqElement, ZqGroup> validElements;
		private ZqElement randomValue;

		@BeforeEach
		void setup() {
			validElements = zqGroupGenerator.generateRandomZqElementVector(KEY_LENGTH);
			randomValue = zqGroupGenerator.genZqElementMember();
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void getCommitmentWithNullParameters() {
			assertThrows(NullPointerException.class, () -> CommitmentService.getCommitment(null, randomValue, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> CommitmentService.getCommitment(validElements, null, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> CommitmentService.getCommitment(validElements, randomValue, null));
		}

		@Test
		@DisplayName("with empty list of values to commit to does not throw")
		void getCommitmentOfEmptyList() {
			SameGroupVector<ZqElement, ZqGroup> values = SameGroupVector.of();
			assertNotNull(CommitmentService.getCommitment(values, randomValue, validCommitmentKey));
		}

		@RepeatedTest(10)
		@DisplayName("with empty list result is multimodexp with padding")
		void withEmptyListResultIsMultiModExpWithPadding() {
			SameGroupVector<ZqElement, ZqGroup> values = SameGroupVector.of();
			List<BigInteger> aPrime = Stream.generate(() -> BigInteger.ZERO).limit(KEY_LENGTH).collect(Collectors.toList());
			aPrime.add(0, randomValue.getValue());
			BigInteger expected = BigIntegerOperations.multiModExp(
					validCommitmentKey.stream().map(GqElement::getValue)
							.collect(Collectors.toList()),
					aPrime,
					gqGroup.getP());
			assertEquals(expected, CommitmentService.getCommitment(values, randomValue, validCommitmentKey).getValue());
		}

		@Test
		@DisplayName("with element list longer than commitment key throws IllegalArgumentException")
		void getCommitmentWithTooLongListOfValues() {
			SameGroupVector<ZqElement, ZqGroup> tooLongList = validElements.append(zqGroup.getIdentity());
			assertThrows(IllegalArgumentException.class, () -> CommitmentService.getCommitment(tooLongList, randomValue, validCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and commitment key in groups of different order throws IllegalArgumentException")
		void getCommitmentWithCommitmentKeyGroupDifferentOrderThanValuesGroup() {
			GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			CommitmentKey differentCommitmentKey = genCommitmentKey(differentGqGroup, KEY_LENGTH);
			assertThrows(IllegalArgumentException.class, () -> CommitmentService.getCommitment(validElements, randomValue, differentCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and random element from different groups throws IllegalArgumentException")
		void getCommitmentWithRandomValueDifferentGroupThanValues() {
			ZqGroup differentZqGroup = new ZqGroup(zqGroup.getQ().multiply(BigInteger.TEN));
			ZqElement differentRandomValue = ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup);
			assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitment(validElements, differentRandomValue, validCommitmentKey));

		}

		@RepeatedTest(100)
		@DisplayName("returns a commitment that belongs to the same group than the commitment key elements")
		void getCommitmentInSameGroupAsCommitmentKey() {
			assertEquals(gqGroup, CommitmentService.getCommitment(validElements, randomValue, validCommitmentKey).getGroup());
		}

		@RepeatedTest(100)
		@DisplayName("returns the same commitment when elements are added to the commitment key")
		void getCommitmentWithLongerCommitmentKeyYieldsSameResult() {
			CommitmentKey longerCommitmentKey = genCommitmentKey(gqGroup, 2 * KEY_LENGTH);
			CommitmentKey exactCommitmentKey =
					new CommitmentKey(longerCommitmentKey.stream().limit(1).collect(Collectors.toList()).get(0),
							longerCommitmentKey.stream().skip(1).limit(KEY_LENGTH).collect(Collectors.toList()));
			GqElement commitmentExactCK = CommitmentService.getCommitment(validElements, randomValue, exactCommitmentKey);
			GqElement commitmentLongerCK = CommitmentService.getCommitment(validElements, randomValue, longerCommitmentKey);
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

			assertEquals(expected, CommitmentService.getCommitment(new SameGroupVector<>(a), r, ck));
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
			validMatrix = zqGroupGenerator.generateRandomZqElementMatrix(n, m);
			validRandomValues = zqGroupGenerator.generateRandomZqElementVector(m);
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void getCommitmentMatrixWithNullParameters() {
			assertThrows(NullPointerException.class, () -> CommitmentService.getCommitmentMatrix(null, validRandomValues, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> CommitmentService.getCommitmentMatrix(validMatrix, null, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> CommitmentService.getCommitmentMatrix(validMatrix, validRandomValues, null));
		}

		@Test
		@DisplayName("with empty elements matrix returns empty list")
		void getCommitmentMatrixWithEmptyElementsMatrix() {
			SameGroupMatrix<ZqElement, ZqGroup> emptyMatrix = zqGroupGenerator.generateRandomZqElementMatrix(0, 0);

			assertEquals(SameGroupVector.of(),
					CommitmentService.getCommitmentMatrix(emptyMatrix, validRandomValues, validCommitmentKey));
		}

		@Test
		@DisplayName("with empty rows in elements matrix returns empty list")
		void getCommitmentMatrixWithEmptyRowsInElementsMatrix() {
			SameGroupMatrix<ZqElement, ZqGroup> emptyRowsMatrix = zqGroupGenerator.generateRandomZqElementMatrix(0, m);
			SameGroupVector<ZqElement, ZqGroup> emptyRandomElements = zqGroupGenerator.generateRandomZqElementVector(0);
			assertEquals(SameGroupVector.of(),
					CommitmentService.getCommitmentMatrix(emptyRowsMatrix, emptyRandomElements, validCommitmentKey));
		}

		@Test
		@DisplayName("with too large matrix throws IllegalArgumentException")
		void getCommitmentMatrixWithTooManyRows() {
			SameGroupMatrix<ZqElement, ZqGroup> tooManyRowsMatrix = zqGroupGenerator.generateRandomZqElementMatrix(n + 1, m);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentMatrix(tooManyRowsMatrix, validRandomValues, validCommitmentKey));
			assertEquals("The commitment key must be longer than the number of rows of the elements matrix", exception.getMessage());
		}

		@Test
		@DisplayName("with matrix group and commitment key group different order throws IllegalArgumentException")
		void getCommitmentMatrixWithCommitmentKeyGroupDifferentOrderThanValuesGroup() {
			GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			CommitmentKey differentCommitmentKey = genCommitmentKey(differentGqGroup, n);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentMatrix(validMatrix, validRandomValues, differentCommitmentKey));
			assertEquals("The commitment key must have the same order (q) than the elements to be committed to and the random values",
					exception.getMessage());
		}

		@Test
		@DisplayName("with matrix group different from random values group throws IllegalArgumentException")
		void getCommitmentWithRandomValueDifferentGroupThanValues() {
			ZqGroup differentZqGroup = new ZqGroup(zqGroup.getQ().multiply(BigInteger.TEN));
			final ZqGroupGenerator differentZqGroupGenerator = new ZqGroupGenerator(differentZqGroup);
			SameGroupVector<ZqElement, ZqGroup> differentRandomValues = differentZqGroupGenerator.generateRandomZqElementVector(m);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentMatrix(validMatrix, differentRandomValues, validCommitmentKey));
			assertEquals("The elements to be committed to and the random elements must be in the same group.", exception.getMessage());
		}

		@RepeatedTest(100)
		@DisplayName("returns commitment vector of the same group than the commitment key")
		void getCommitmentMatrixInSameGroupAsCommitmentKey() {
			final SameGroupVector<GqElement, GqGroup> commitment = CommitmentService
					.getCommitmentMatrix(validMatrix, validRandomValues, validCommitmentKey);
			GqGroup commitmentGroup = commitment.get(0).getGroup();
			assertEquals(gqGroup, commitmentGroup);
		}

		@RepeatedTest(100)
		@DisplayName("returns the same commitment when elements are added to the commitment key")
		void getCommitmentMatrixWithLongerCommitmentKeyYieldsSameResult() {
			CommitmentKey longerCommitmentKey = genCommitmentKey(gqGroup, 2 * n);
			CommitmentKey exactCommitmentKey =
					new CommitmentKey(longerCommitmentKey.stream().limit(1).collect(Collectors.toList()).get(0),
							longerCommitmentKey.stream().skip(1).limit(KEY_LENGTH).collect(Collectors.toList()));
			SameGroupVector<GqElement, GqGroup> commitmentExactCK = CommitmentService
					.getCommitmentMatrix(validMatrix, validRandomValues, exactCommitmentKey);
			SameGroupVector<GqElement, GqGroup> commitmentLongerCK = CommitmentService
					.getCommitmentMatrix(validMatrix, validRandomValues, longerCommitmentKey);
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

			assertEquals(new SameGroupVector<>(expected), CommitmentService.getCommitmentMatrix(a, r, ck));
		}
	}

	@Nested
	@DisplayName("getCommitmentVector")
	class GetCommitmentVectorTest {

		private SameGroupVector<ZqElement, ZqGroup> validElements;
		private SameGroupVector<ZqElement, ZqGroup> validRandomElements;

		@BeforeEach
		void setup() {
			validElements = zqGroupGenerator.generateRandomZqElementVector(KEY_LENGTH);
			validRandomElements = zqGroupGenerator.generateRandomZqElementVector(KEY_LENGTH);
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void getCommitmentVectorWithNullParameters() {
			assertThrows(NullPointerException.class, () -> CommitmentService.getCommitmentVector(null, validRandomElements, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> CommitmentService.getCommitmentVector(validElements, null, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> CommitmentService.getCommitmentVector(validElements, validRandomElements, null));
		}

		@Test
		@DisplayName("with element list longer than commitment key throws IllegalArgumentException")
		void getCommitmentVectorWithTooLongListOfValues() {
			final SameGroupVector<ZqElement, ZqGroup> tooLongList = validElements.append(zqGroup.getIdentity());
			assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentVector(tooLongList, validRandomElements, validCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and commitment key in groups of different order throws IllegalArgumentException")
		void getCommitmentVectorWithCommitmentKeyGroupDifferentOrderThanValuesGroup() {
			GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
			CommitmentKey differentCommitmentKey = genCommitmentKey(differentGqGroup, KEY_LENGTH);
			assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentVector(validElements, validRandomElements, differentCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and random elements from different groups throws IllegalArgumentException")
		void getCommitmentVectorWithRandomValueDifferentGroupThanValues() {
			final ZqGroup differentZqGroup = getDifferentZqGroup();
			final ZqGroupGenerator differentZqGroupGenerator = new ZqGroupGenerator(differentZqGroup);
			final SameGroupVector<ZqElement, ZqGroup> differentRandomElements = differentZqGroupGenerator.generateRandomZqElementVector(KEY_LENGTH);
			assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentVector(validElements, differentRandomElements, validCommitmentKey));
		}

		@RepeatedTest(100)
		@DisplayName("returns a commitment that belongs to the same group than the commitment key elements")
		void getCommitmentVectorInSameGroupAsCommitmentKey() {
			SameGroupVector<GqElement, GqGroup> commitment = CommitmentService
					.getCommitmentVector(validElements, validRandomElements, validCommitmentKey);
			assertTrue(commitment.stream().map(GqElement::getGroup).allMatch(gqGroup::equals));
		}

		@RepeatedTest(100)
		@DisplayName("returns the same commitment when elements are added to the commitment key")
		void getCommitmentVectorWithLongerCommitmentKeyYieldsSameResult() {
			CommitmentKey longerCommitmentKey = genCommitmentKey(gqGroup, 2 * KEY_LENGTH);
			CommitmentKey exactCommitmentKey =
					new CommitmentKey(longerCommitmentKey.stream().limit(1).collect(Collectors.toList()).get(0),
							longerCommitmentKey.stream().skip(1).limit(KEY_LENGTH).collect(Collectors.toList()));
			SameGroupVector<GqElement, GqGroup> commitmentExactCK = CommitmentService
					.getCommitmentVector(validElements, validRandomElements, exactCommitmentKey);
			SameGroupVector<GqElement, GqGroup> commitmentLongerCK = CommitmentService
					.getCommitmentVector(validElements, validRandomElements, longerCommitmentKey);
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

			assertEquals(new SameGroupVector<>(expected),
					CommitmentService.getCommitmentVector(new SameGroupVector<>(a), new SameGroupVector<>(r), ck));
		}
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
