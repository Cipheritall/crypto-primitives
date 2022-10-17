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
package ch.post.it.evoting.cryptoprimitives.internal.mixnet;

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
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

import ch.post.it.evoting.cryptoprimitives.internal.math.BigIntegerOperationsService;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class CommitmentServiceTest {

	private static final int KEY_LENGTH = 5; // This must be >= 2
	private static final RandomService randomService = new RandomService();
	private static final SecureRandom secureRandom = new SecureRandom();

	private static ZqGroupGenerator zqGroupGenerator;

	private GqGroup gqGroup;
	private ZqGroup zqGroup;
	private CommitmentKey validCommitmentKey;
	private TestCommitmentKeyGenerator ckGenerator;

	@BeforeEach
	void setup() {
		gqGroup = GroupTestData.getGqGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		zqGroupGenerator = new ZqGroupGenerator(zqGroup);
		ckGenerator = new TestCommitmentKeyGenerator(gqGroup);
		validCommitmentKey = ckGenerator.genCommitmentKey(KEY_LENGTH);
	}

	@Nested
	@DisplayName("getCommitment")
	class GetCommitmentTest {

		private GroupVector<ZqElement, ZqGroup> validElements;
		private ZqElement randomValue;

		@BeforeEach
		void setup() {
			validElements = zqGroupGenerator.genRandomZqElementVector(KEY_LENGTH);
			randomValue = zqGroupGenerator.genRandomZqElementMember();
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
			final GroupVector<ZqElement, ZqGroup> values = GroupVector.of();
			assertThrows(IllegalArgumentException.class, () -> CommitmentService.getCommitment(values, randomValue, validCommitmentKey));
		}

		@RepeatedTest(10)
		@DisplayName("with list containing zeroes result is multimodexp with padding")
		void withEmptyListResultIsMultiModExpWithPadding() {
			final GroupVector<ZqElement, ZqGroup> values = Stream.generate(() -> ZqElement.create(BigInteger.ZERO, zqGroup))
					.limit(KEY_LENGTH)
					.collect(GroupVector.toGroupVector());
			final List<BigInteger> aPrime = Stream.generate(() -> BigInteger.ZERO).limit(KEY_LENGTH).collect(Collectors.toList());
			aPrime.add(0, randomValue.getValue());
			final BigInteger expected = BigIntegerOperationsService.multiModExp(
					validCommitmentKey.stream().map(GqElement::getValue)
							.collect(Collectors.toList()),
					aPrime,
					gqGroup.getP());
			assertEquals(expected, CommitmentService.getCommitment(values, randomValue, validCommitmentKey).getValue());
		}

		@Test
		@DisplayName("with element list longer than commitment key throws IllegalArgumentException")
		void getCommitmentWithTooLongListOfValues() {
			final GroupVector<ZqElement, ZqGroup> tooLongList = validElements.append(zqGroup.getIdentity());
			assertThrows(IllegalArgumentException.class, () -> CommitmentService.getCommitment(tooLongList, randomValue, validCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and commitment key in groups of different order throws IllegalArgumentException")
		void getCommitmentWithCommitmentKeyGroupDifferentOrderThanValuesGroup() {
			final GqGroup differentGqGroup = GroupTestData.getDifferentGqGroup(gqGroup);
			final TestCommitmentKeyGenerator otherGenerator = new TestCommitmentKeyGenerator(differentGqGroup);
			final CommitmentKey differentCommitmentKey = otherGenerator.genCommitmentKey(KEY_LENGTH);
			assertThrows(IllegalArgumentException.class, () -> CommitmentService.getCommitment(validElements, randomValue, differentCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and random element from different groups throws IllegalArgumentException")
		void getCommitmentWithRandomValueDifferentGroupThanValues() {
			final ZqGroup differentZqGroup = new ZqGroup(zqGroup.getQ().multiply(BigInteger.TEN));
			final ZqElement differentRandomValue = ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup);
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
			final CommitmentKey longerCommitmentKey = ckGenerator.genCommitmentKey(2 * KEY_LENGTH);
			final CommitmentKey exactCommitmentKey =
					new CommitmentKey(longerCommitmentKey.stream().limit(1).toList().get(0),
							longerCommitmentKey.stream().skip(1).limit(KEY_LENGTH).collect(GroupVector.toGroupVector()));
			final GqElement commitmentExactCK = CommitmentService.getCommitment(validElements, randomValue, exactCommitmentKey);
			final GqElement commitmentLongerCK = CommitmentService.getCommitment(validElements, randomValue, longerCommitmentKey);
			assertEquals(commitmentExactCK, commitmentLongerCK);
		}

		@Test
		@DisplayName("with simple values returns expected result")
		void getCommitmentWithSpecificValues() {

			final GqGroup specificGqGroup = new GqGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(6));
			final ZqGroup specificZqGroup = ZqGroup.sameOrderAs(specificGqGroup);
			// a = (2, 10)
			final List<ZqElement> a = new ArrayList<>();
			a.add(ZqElement.create(BigInteger.valueOf(2), specificZqGroup));
			a.add(ZqElement.create(BigInteger.TEN, specificZqGroup));
			// r = 5
			final ZqElement r = ZqElement.create(BigInteger.valueOf(5), specificZqGroup);
			// ck = (2, 3, 4)
			final List<GqElement> gElements = new ArrayList<>(2);
			final GqElement h = GqElementFactory.fromValue(BigInteger.valueOf(2), specificGqGroup);
			gElements.add(GqElementFactory.fromValue(BigInteger.valueOf(3), specificGqGroup));
			gElements.add(GqElementFactory.fromValue(BigInteger.valueOf(4), specificGqGroup));
			final CommitmentKey ck = new CommitmentKey(h, GroupVector.from(gElements));
			// c = 3
			final GqElement expected = GqElementFactory.fromValue(BigInteger.valueOf(3), specificGqGroup);

			assertEquals(expected, CommitmentService.getCommitment(GroupVector.from(a), r, ck));
		}
	}

	@Nested
	@DisplayName("getCommitmentMatrix")
	class GetCommitmentMatrixTest {

		private int m;
		private int n;

		private GroupMatrix<ZqElement, ZqGroup> validMatrix;
		private GroupVector<ZqElement, ZqGroup> validRandomValues;

		@BeforeEach
		void setup() {
			m = secureRandom.nextInt(10) + 1;
			n = KEY_LENGTH;
			validMatrix = zqGroupGenerator.genRandomZqElementMatrix(n, m);
			validRandomValues = zqGroupGenerator.genRandomZqElementVector(m);
		}

		@Test
		@DisplayName("with any null parameter throws NullPointerException")
		void getCommitmentMatrixWithNullParameters() {
			assertThrows(NullPointerException.class, () -> CommitmentService.getCommitmentMatrix(null, validRandomValues, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> CommitmentService.getCommitmentMatrix(validMatrix, null, validCommitmentKey));
			assertThrows(NullPointerException.class, () -> CommitmentService.getCommitmentMatrix(validMatrix, validRandomValues, null));
		}

		@Test
		@DisplayName("with too large matrix throws IllegalArgumentException")
		void getCommitmentMatrixWithTooManyRows() {
			final GroupMatrix<ZqElement, ZqGroup> tooManyRowsMatrix = zqGroupGenerator.genRandomZqElementMatrix(n + 1, m);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentMatrix(tooManyRowsMatrix, validRandomValues, validCommitmentKey));
			assertEquals("The commitment key must be longer than the number of rows of the elements matrix", exception.getMessage());
		}

		@Test
		@DisplayName("with matrix group and commitment key group different order throws IllegalArgumentException")
		void getCommitmentMatrixWithCommitmentKeyGroupDifferentOrderThanValuesGroup() {
			final GqGroup differentGqGroup = GroupTestData.getDifferentGqGroup(gqGroup);
			final TestCommitmentKeyGenerator otherGenerator = new TestCommitmentKeyGenerator(differentGqGroup);
			final CommitmentKey differentCommitmentKey = otherGenerator.genCommitmentKey(n);
			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentMatrix(validMatrix, validRandomValues, differentCommitmentKey));
			assertEquals("The commitment key must have the same order (q) than the elements to be committed to and the random values",
					exception.getMessage());
		}

		@Test
		@DisplayName("with matrix group different from random values group throws IllegalArgumentException")
		void getCommitmentWithRandomValueDifferentGroupThanValues() {
			final ZqGroup differentZqGroup = new ZqGroup(zqGroup.getQ().multiply(BigInteger.TEN));
			final ZqGroupGenerator differentZqGroupGenerator = new ZqGroupGenerator(differentZqGroup);
			final GroupVector<ZqElement, ZqGroup> differentRandomValues = differentZqGroupGenerator.genRandomZqElementVector(m);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentMatrix(validMatrix, differentRandomValues, validCommitmentKey));
			assertEquals("The elements to be committed to and the random elements must be in the same group", exception.getMessage());
		}

		@RepeatedTest(100)
		@DisplayName("returns commitment vector of the same group than the commitment key")
		void getCommitmentMatrixInSameGroupAsCommitmentKey() {
			final GroupVector<GqElement, GqGroup> commitment = CommitmentService
					.getCommitmentMatrix(validMatrix, validRandomValues, validCommitmentKey);
			final GqGroup commitmentGroup = commitment.get(0).getGroup();
			assertEquals(gqGroup, commitmentGroup);
		}

		@RepeatedTest(100)
		@DisplayName("returns the same commitment when elements are added to the commitment key")
		void getCommitmentMatrixWithLongerCommitmentKeyYieldsSameResult() {
			final CommitmentKey longerCommitmentKey = ckGenerator.genCommitmentKey(2 * n);
			final CommitmentKey exactCommitmentKey =
					new CommitmentKey(longerCommitmentKey.stream().limit(1).toList().get(0),
							longerCommitmentKey.stream().skip(1).limit(KEY_LENGTH).collect(GroupVector.toGroupVector()));
			final GroupVector<GqElement, GqGroup> commitmentExactCK = CommitmentService
					.getCommitmentMatrix(validMatrix, validRandomValues, exactCommitmentKey);
			final GroupVector<GqElement, GqGroup> commitmentLongerCK = CommitmentService
					.getCommitmentMatrix(validMatrix, validRandomValues, longerCommitmentKey);
			assertEquals(commitmentExactCK, commitmentLongerCK);
		}

		@Test
		void getCommitmentMatrixWithSpecificValues() {

			final GqGroup specificGqGroup = new GqGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(6));
			final ZqGroup specificZqGroup = ZqGroup.sameOrderAs(specificGqGroup);
			// a0 = (2, 10)
			final List<ZqElement> a0 = new ArrayList<>(2);
			a0.add(ZqElement.create(BigInteger.valueOf(2), specificZqGroup));
			a0.add(ZqElement.create(BigInteger.TEN, specificZqGroup));
			// a1 = (3, 4)
			final List<ZqElement> a1 = new ArrayList<>(2);
			a1.add(ZqElement.create(BigInteger.valueOf(8), specificZqGroup));
			a1.add(ZqElement.create(BigInteger.valueOf(9), specificZqGroup));
			// a = (a0, a1)
			final GroupMatrix<ZqElement, ZqGroup> a = GroupMatrix.fromColumns(Arrays.asList(a0, a1));
			// r = (5, 8)
			final List<ZqElement> rValues = new ArrayList<>(2);
			rValues.add(ZqElement.create(BigInteger.valueOf(5), specificZqGroup));
			rValues.add(ZqElement.create(BigInteger.valueOf(8), specificZqGroup));
			final GroupVector<ZqElement, ZqGroup> r = GroupVector.from(rValues);
			// ck = (2, 3, 4)
			final List<GqElement> gElements = new ArrayList<>();
			final GqElement h = GqElementFactory.fromValue(BigInteger.valueOf(2), specificGqGroup);
			gElements.add(GqElementFactory.fromValue(BigInteger.valueOf(3), specificGqGroup));
			gElements.add(GqElementFactory.fromValue(BigInteger.valueOf(4), specificGqGroup));
			final CommitmentKey ck = new CommitmentKey(h, GroupVector.from(gElements));
			// c = (3, 4)
			final List<GqElement> expected = new ArrayList<>(2);
			expected.add(GqElementFactory.fromValue(BigInteger.valueOf(3), specificGqGroup));
			expected.add(GqElementFactory.fromValue(BigInteger.valueOf(4), specificGqGroup));

			assertEquals(GroupVector.from(expected), CommitmentService.getCommitmentMatrix(a, r, ck));
		}
	}

	@Nested
	@DisplayName("getCommitmentVector")
	class GetCommitmentVectorTest {

		private GroupVector<ZqElement, ZqGroup> validElements;
		private GroupVector<ZqElement, ZqGroup> validRandomElements;

		@BeforeEach
		void setup() {
			validElements = zqGroupGenerator.genRandomZqElementVector(KEY_LENGTH);
			validRandomElements = zqGroupGenerator.genRandomZqElementVector(KEY_LENGTH);
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
			final GroupVector<ZqElement, ZqGroup> tooLongList = validElements.append(zqGroup.getIdentity());
			assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentVector(tooLongList, validRandomElements, validCommitmentKey));
		}

		@Test
		@DisplayName("with lists of even size throws IllegalArgumentException")
		void getCommitmentVectorWithPairListOfValues() {
			final CommitmentKey pairValidCommitmentKey = ckGenerator.genCommitmentKey(KEY_LENGTH + 1);
			final GroupVector<ZqElement, ZqGroup> pairValidElements = zqGroupGenerator.genRandomZqElementVector(KEY_LENGTH + 1);
			final GroupVector<ZqElement, ZqGroup> pairRandomValidElements = zqGroupGenerator.genRandomZqElementVector(KEY_LENGTH + 1);
			assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentVector(pairValidElements, pairRandomValidElements, pairValidCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and commitment key in groups of different order throws IllegalArgumentException")
		void getCommitmentVectorWithCommitmentKeyGroupDifferentOrderThanValuesGroup() {
			final GqGroup differentGqGroup = GroupTestData.getDifferentGqGroup(gqGroup);
			final TestCommitmentKeyGenerator otherCkGenerator = new TestCommitmentKeyGenerator(differentGqGroup);
			final CommitmentKey differentCommitmentKey = otherCkGenerator.genCommitmentKey(KEY_LENGTH);
			assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentVector(validElements, validRandomElements, differentCommitmentKey));
		}

		@Test
		@DisplayName("with elements to be committed to and random elements from different groups throws IllegalArgumentException")
		void getCommitmentVectorWithRandomValueDifferentGroupThanValues() {
			final ZqGroup differentZqGroup = GroupTestData.getDifferentZqGroup(zqGroup);
			final ZqGroupGenerator differentZqGroupGenerator = new ZqGroupGenerator(differentZqGroup);
			final GroupVector<ZqElement, ZqGroup> differentRandomElements = differentZqGroupGenerator.genRandomZqElementVector(KEY_LENGTH);
			assertThrows(IllegalArgumentException.class,
					() -> CommitmentService.getCommitmentVector(validElements, differentRandomElements, validCommitmentKey));
		}

		@RepeatedTest(100)
		@DisplayName("returns a commitment that belongs to the same group than the commitment key elements")
		void getCommitmentVectorInSameGroupAsCommitmentKey() {
			final GroupVector<GqElement, GqGroup> commitment = CommitmentService
					.getCommitmentVector(validElements, validRandomElements, validCommitmentKey);
			assertTrue(commitment.stream().map(GqElement::getGroup).allMatch(gqGroup::equals));
		}

		@RepeatedTest(100)
		@DisplayName("returns the same commitment when elements are added to the commitment key")
		void getCommitmentVectorWithLongerCommitmentKeyYieldsSameResult() {
			final CommitmentKey longerCommitmentKey = ckGenerator.genCommitmentKey(2 * KEY_LENGTH);
			final CommitmentKey exactCommitmentKey =
					new CommitmentKey(longerCommitmentKey.stream().limit(1).toList().get(0),
							longerCommitmentKey.stream().skip(1).limit(KEY_LENGTH).collect(GroupVector.toGroupVector()));
			final GroupVector<GqElement, GqGroup> commitmentExactCK = CommitmentService
					.getCommitmentVector(validElements, validRandomElements, exactCommitmentKey);
			final GroupVector<GqElement, GqGroup> commitmentLongerCK = CommitmentService
					.getCommitmentVector(validElements, validRandomElements, longerCommitmentKey);
			assertEquals(commitmentExactCK, commitmentLongerCK);
		}

		@Test
		@DisplayName("with simple values returns expected result")
		void getCommitmentVectorWithSpecificValues() {

			final GqGroup specificGqGroup = new GqGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(6));
			final ZqGroup specificZqGroup = ZqGroup.sameOrderAs(specificGqGroup);
			// a = (2, 10, 8)
			final List<ZqElement> a = new ArrayList<>(3);
			a.add(ZqElement.create(BigInteger.valueOf(2), specificZqGroup));
			a.add(ZqElement.create(BigInteger.TEN, specificZqGroup));
			a.add(ZqElement.create(BigInteger.valueOf(8), specificZqGroup));
			// r = (5, 8, 3)
			final List<ZqElement> r = new ArrayList<>(3);
			r.add(ZqElement.create(BigInteger.valueOf(5), specificZqGroup));
			r.add(ZqElement.create(BigInteger.valueOf(8), specificZqGroup));
			r.add(ZqElement.create(BigInteger.valueOf(3), specificZqGroup));
			// ck = (2, 3, 8)
			final List<GqElement> gElements = new ArrayList<>(3);
			final GqElement h = GqElementFactory.fromValue(BigInteger.valueOf(2), specificGqGroup);
			gElements.add(GqElementFactory.fromValue(BigInteger.valueOf(3), specificGqGroup));
			gElements.add(GqElementFactory.fromValue(BigInteger.valueOf(8), specificGqGroup));
			final CommitmentKey ck = new CommitmentKey(h, GroupVector.from(gElements));
			// c = (12, 1, 2)
			final List<GqElement> expected = new ArrayList<>(3);
			expected.add(GqElementFactory.fromValue(BigInteger.valueOf(12), specificGqGroup));
			expected.add(GqElementFactory.fromValue(BigInteger.ONE, specificGqGroup));
			expected.add(GqElementFactory.fromValue(BigInteger.valueOf(2), specificGqGroup));

			assertEquals(GroupVector.from(expected),
					CommitmentService.getCommitmentVector(GroupVector.from(a), GroupVector.from(r), ck));
		}
	}
}
