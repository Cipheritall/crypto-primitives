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
package ch.post.it.evoting.cryptoprimitives;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestSizedElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.math.TestGroup;

class GroupVectorTest {

	static SecureRandom random = new SecureRandom();

	@Test
	void testOf() {
		TestGroup group = new TestGroup();
		TestGroupElement e1 = new TestGroupElement(group);
		TestGroupElement e2 = new TestGroupElement(group);

		final GroupVector<TestGroupElement, TestGroup> groupVector = GroupVector.of(e1, e2);
		assertEquals(2, groupVector.size());

		final GroupVector<TestGroupElement, TestGroup> emptyGroupVector = GroupVector.of();
		assertEquals(0, emptyGroupVector.size());
	}

	@Test
	void testOfWithInvalidParametersThrows() {
		assertThrows(NullPointerException.class, () -> GroupVector.of(null));

		// With null elem.
		TestGroup group = new TestGroup();
		TestGroupElement e1 = new TestGroupElement(group);
		final IllegalArgumentException nullIllegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> GroupVector.of(e1, null));
		assertEquals("Elements must not contain nulls", nullIllegalArgumentException.getMessage());

		// Different group elems.
		TestGroupElement e2 = new TestGroupElement(new TestGroup());
		final IllegalArgumentException diffGroupIllegalArgumentException2 = assertThrows(IllegalArgumentException.class,
				() -> GroupVector.of(e1, e2));
		assertEquals("All elements must belong to the same group.", diffGroupIllegalArgumentException2.getMessage());
	}

	@Test
	void testNullElementsThrows() {
		assertThrows(NullPointerException.class, () -> GroupVector.from(null));
	}

	@Test
	void testEmptyElementsDoesNotThrow() {
		GroupVector<TestGroupElement, TestGroup> vector = GroupVector.of();
		assertEquals(0, vector.size());
	}

	@Test
	void testGroupOfEmptyVectorThrows() {
		GroupVector<TestGroupElement, TestGroup> vector = GroupVector.of();
		assertThrows(IllegalStateException.class, vector::getGroup);
	}

	@Test
	void testElementsWithNullThrows() {
		List<TestGroupElement> elements = new ArrayList<>(Collections.emptyList());
		elements.add(null);
		assertThrows(IllegalArgumentException.class, () -> GroupVector.from(elements));
	}

	@Test
	void testElementsWithValueAndNullThrows() {
		TestGroup group = new TestGroup();
		TestGroupElement validElement = new TestGroupElement(group);
		List<TestGroupElement> elements = Arrays.asList(validElement, null);
		assertThrows(IllegalArgumentException.class, () -> GroupVector.from(elements));
	}

	@Test
	void testElementsOfDifferentGroupsThrows() {
		TestGroup group1 = new TestGroup();
		TestGroupElement first = new TestGroupElement(group1);
		TestGroup group2 = new TestGroup();
		TestGroupElement second = new TestGroupElement(group2);
		List<TestGroupElement> elements = Arrays.asList(first, second);
		assertThrows(IllegalArgumentException.class, () -> GroupVector.from(elements));
	}

	@Test
	void testElementsOfDifferentSizeThrows() {
		TestGroup group = new TestGroup();
		TestSizedElement first = new TestSizedElement(group, 1);
		TestSizedElement second = new TestSizedElement(group, 2);
		List<TestSizedElement> elements = Arrays.asList(first, second);
		assertThrows(IllegalArgumentException.class, () -> GroupVector.from(elements));
	}

	@Test
	void testLengthReturnsElementsLength() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestGroupElement> elements =
				Stream
						.generate(() -> new TestGroupElement(group))
						.limit(n)
						.collect(Collectors.toList());
		assertEquals(n, GroupVector.from(elements).size());
	}

	@Test
	void testGetElementReturnsElement() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestGroupElement> elements = Stream.generate(() -> new TestGroupElement(group)).limit(n).collect(Collectors.toList());
		int i = random.nextInt(n);
		assertEquals(elements.get(i), GroupVector.from(elements).get(i));
	}

	@Test
	void testGetElementAboveRangeThrows() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestGroupElement> elements = Stream.generate(() -> new TestGroupElement(group)).limit(n).collect(Collectors.toList());
		GroupVector<TestGroupElement, TestGroup> actor = GroupVector.from(elements);
		assertThrows(IndexOutOfBoundsException.class, () -> actor.get(n));
	}

	@Test
	void testGetElementBelowRangeThrows() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestGroupElement> elements = Stream.generate(() -> new TestGroupElement(group)).limit(n).collect(Collectors.toList());
		GroupVector<TestGroupElement, TestGroup> actor = GroupVector.from(elements);
		assertThrows(IndexOutOfBoundsException.class, () -> actor.get(-1));
	}

	@Test
	void testGetGroupReturnsElementsGroup() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestGroupElement> elements = Stream.generate(() -> new TestGroupElement(group)).limit(n).collect(Collectors.toList());
		GroupVector<TestGroupElement, TestGroup> actor = GroupVector.from(elements);
		assertEquals(group, actor.getGroup());
	}

	@Test
	void givenElementsWhenGetElementsThenExpectedElements() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestGroupElement> elements = Stream.generate(() -> new TestGroupElement(group)).limit(n).collect(Collectors.toList());
		GroupVector<TestGroupElement, TestGroup> actor = GroupVector.from(elements);
		assertEquals(elements, new ArrayList<>(actor));
	}

	@Test
	void givenAPropertyHoldsForAnEmptyVector() {
		GroupVector<TestGroupElement, ?> empty = GroupVector.of();
		SecureRandom random = new SecureRandom();
		Function<TestGroupElement, ?> randomFunction = ignored -> random.nextInt();
		assertTrue(empty.allEqual(randomFunction));
	}

	@Test
	void threeElementsWithTheSamePropertyAreAllEqualAndDifferentPropertiesNotEqual() {
		TestGroup group = new TestGroup();
		TestValuedElement first = new TestValuedElement(BigInteger.valueOf(1), group);
		TestValuedElement second = new TestValuedElement(BigInteger.valueOf(2), group);
		TestValuedElement third = new TestValuedElement(BigInteger.valueOf(3), group);
		List<TestValuedElement> elements = Arrays.asList(first, second, third);
		GroupVector<TestValuedElement, TestGroup> vector = GroupVector.from(elements);
		assertAll(() -> {
			assertFalse(vector.allEqual(TestValuedElement::getValue));
			assertTrue(vector.allEqual(TestValuedElement::getGroup));
		});
	}

	@Test
	void isEmptyReturnsTrueForEmptyVector() {
		List<TestGroupElement> elements = Collections.emptyList();
		GroupVector<TestGroupElement, TestGroup> vector = GroupVector.from(elements);
		assertTrue(vector.isEmpty());
	}

	@Test
	void isEmptyReturnsFalseForNonEmptyVector() {
		TestGroup group = new TestGroup();
		List<TestGroupElement> elements = Collections.singletonList(new TestGroupElement(group));
		GroupVector<TestGroupElement, TestGroup> vector = GroupVector.from(elements);
		assertFalse(vector.isEmpty());
	}

	@Test
	void appendWithInvalidParamsThrows() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(10) + 1;
		List<TestGroupElement> elements = Stream.generate(() -> new TestGroupElement(group)).limit(n).collect(Collectors.toList());
		GroupVector<TestGroupElement, TestGroup> groupVector = GroupVector.from(elements);

		assertThrows(NullPointerException.class, () -> groupVector.append(null));

		final TestGroupElement element = new TestGroupElement(new TestGroup());
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> groupVector.append(element));
		assertEquals("The element to append must be in the same group.", illegalArgumentException.getMessage());
	}

	@Test
	void appendWithDifferentSizeThrows() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(10) + 1;
		List<TestSizedElement> elements = Stream.generate(() -> new TestSizedElement(group, 1)).limit(n).collect(Collectors.toList());
		GroupVector<TestSizedElement, TestGroup> groupVector = GroupVector.from(elements);

		final TestSizedElement element = new TestSizedElement(group, 2);
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class, () -> groupVector.append(element));
		assertEquals("The element to append must be the same size.", illegalArgumentException.getMessage());
	}

	@RepeatedTest(10)
	void appendCorrectlyAppends() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(10) + 1;
		List<TestGroupElement> elements = Stream.generate(() -> new TestGroupElement(group)).limit(n).collect(Collectors.toList());
		GroupVector<TestGroupElement, TestGroup> groupVector = GroupVector.from(elements);

		final TestGroupElement element = new TestGroupElement(group);
		final GroupVector<TestGroupElement, TestGroup> augmentedVector = groupVector.append(element);

		assertEquals(groupVector.size() + 1, augmentedVector.size());
		assertEquals(element, augmentedVector.get(n));
	}

	@Test
	void prependWithInvalidParamsThrows() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(10) + 1;
		List<TestGroupElement> elements = Stream.generate(() -> new TestGroupElement(group)).limit(n).collect(Collectors.toList());
		GroupVector<TestGroupElement, TestGroup> groupVector = GroupVector.from(elements);

		assertThrows(NullPointerException.class, () -> groupVector.prepend(null));

		final TestGroupElement element = new TestGroupElement(new TestGroup());
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class, () -> groupVector.prepend(element));
		assertEquals("The element to prepend must be in the same group.", illegalArgumentException.getMessage());
	}

	@Test
	void prependWithDifferentSizeThrows() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(10) + 1;
		List<TestSizedElement> elements = Stream.generate(() -> new TestSizedElement(group, 1)).limit(n).collect(Collectors.toList());
		GroupVector<TestSizedElement, TestGroup> groupVector = GroupVector.from(elements);

		final TestSizedElement element = new TestSizedElement(group, 2);
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class, () -> groupVector.prepend(element));
		assertEquals("The element to prepend must be the same size.", illegalArgumentException.getMessage());
	}

	@RepeatedTest(10)
	void prependCorrectlyPrepends() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(10) + 1;
		List<TestGroupElement> elements = Stream.generate(() -> new TestGroupElement(group)).limit(n).collect(Collectors.toList());
		GroupVector<TestGroupElement, TestGroup> groupVector = GroupVector.from(elements);

		final TestGroupElement element = new TestGroupElement(group);
		final GroupVector<TestGroupElement, TestGroup> augmentedVector = groupVector.prepend(element);

		assertEquals(groupVector.size() + 1, augmentedVector.size());
		assertEquals(element, augmentedVector.get(0));
	}

	@Test
	void toSameGroupVectorCorrectlyCollects() {
		int n = random.nextInt(10) + 1;
		TestGroup group = new TestGroup();
		List<TestGroupElement> elements = Stream.generate(() -> new TestGroupElement(group)).limit(n).collect(Collectors.toList());
		GroupVector<TestGroupElement, TestGroup> actual = elements.stream().collect(GroupVector.toGroupVector());
		GroupVector<TestGroupElement, TestGroup> expected = GroupVector.from(elements);

		assertEquals(expected, actual);
	}

	private static class TestValuedElement extends GroupElement<TestGroup> {
		protected TestValuedElement(BigInteger value, TestGroup group) {
			super(value, group);
		}
	}

	@Nested
	@DisplayName("Transforming a vector of ciphertext into a matrix of ciphertexts...")
	class ToMatrixTest {

		private static final int BOUND_MATRIX_SIZE = 10;

		private int m;
		private int n;

		private TestGroup group;
		private GroupVector<TestGroupElement, TestGroup> groupVector;

		@BeforeEach
		void setup() {
			m = random.nextInt(BOUND_MATRIX_SIZE) + 1;
			n = random.nextInt(BOUND_MATRIX_SIZE) + 1;

			group = new TestGroup();
			List<TestGroupElement> elements = Stream.generate(() -> new TestGroupElement(group)).limit((long) n * m)
					.collect(Collectors.toList());
			groupVector = GroupVector.from(elements);
		}

		@Test
		@DisplayName("with negative number of rows or columns throws IllegalArgumentException")
		void toMatrixWithInvalidNumRowsOrColumns() {
			Exception exception = assertThrows(IllegalArgumentException.class, () -> groupVector.toMatrix(-m, n));
			assertEquals("The number of rows must be positive.", exception.getMessage());
			exception = assertThrows(IllegalArgumentException.class, () -> groupVector.toMatrix(m, -n));
			assertEquals("The number of columns must be positive.", exception.getMessage());
		}

		@Test
		@DisplayName("with incompatible decomposition into rows and columns throws an IllegalArgumentException")
		void toMatrixWithWrongN() {
			Exception exception = assertThrows(IllegalArgumentException.class, () -> groupVector.toMatrix(m + 1, n));
			assertEquals("The vector of ciphertexts must be decomposable into m rows and n columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with valid input yields expected result")
		void toMatrixTest() {
			GroupMatrix<TestGroupElement, TestGroup> matrix = groupVector.toMatrix(m, n);

			for (int i = 0; i < m; i++) {
				for (int j = 0; j < n; j++) {
					assertEquals(groupVector.get(i + m * j), matrix.get(i, j));
				}
			}
		}
	}
}
