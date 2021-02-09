/*
 * HEADER_LICENSE_OPEN_SOURCE
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
import ch.post.it.evoting.cryptoprimitives.test.tools.TestHasGroupElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.math.TestGroup;

class SameGroupVectorTest {

	static SecureRandom random = new SecureRandom();

	@Test
	void testOf() {
		TestGroup group = new TestGroup();
		TestHasGroupElement e1 = new TestHasGroupElement(group);
		TestHasGroupElement e2 = new TestHasGroupElement(group);

		final SameGroupVector<TestHasGroupElement, TestGroup> sameGroupVector = SameGroupVector.of(e1, e2);
		assertEquals(2, sameGroupVector.size());

		final SameGroupVector<TestHasGroupElement, TestGroup> emptySameGroupVector = SameGroupVector.of();
		assertEquals(0, emptySameGroupVector.size());
	}

	@Test
	void testOfWithInvalidParametersThrows() {
		assertThrows(NullPointerException.class, () -> SameGroupVector.of(null));

		// With null elem.
		TestGroup group = new TestGroup();
		TestHasGroupElement e1 = new TestHasGroupElement(group);
		final IllegalArgumentException nullIllegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> SameGroupVector.of(e1, null));
		assertEquals("Elements must not contain nulls", nullIllegalArgumentException.getMessage());

		// Different group elems.
		TestHasGroupElement e2 = new TestHasGroupElement(new TestGroup());
		final IllegalArgumentException diffGroupIllegalArgumentException2 = assertThrows(IllegalArgumentException.class,
				() -> SameGroupVector.of(e1, e2));
		assertEquals("All elements must belong to the same group.", diffGroupIllegalArgumentException2.getMessage());
	}

	@Test
	void testNullElementsThrows() {
		assertThrows(NullPointerException.class, () -> new SameGroupVector<TestHasGroupElement, TestGroup>(null));
	}

	@Test
	void testEmptyElementsDoesNotThrow() {
		SameGroupVector<TestHasGroupElement, TestGroup> vector = SameGroupVector.of();
		assertEquals(0, vector.size());
	}

	@Test
	void testGroupOfEmptyVectorThrows() {
		SameGroupVector<TestHasGroupElement, TestGroup> vector = SameGroupVector.of();
		assertThrows(IllegalStateException.class, vector::getGroup);
	}

	@Test
	void testElementsWithNullThrows() {
		List<TestHasGroupElement> elements = new ArrayList<>(Collections.emptyList());
		elements.add(null);
		assertThrows(IllegalArgumentException.class, () -> new SameGroupVector<>(elements));
	}

	@Test
	void testElementsWithValueAndNullThrows() {
		TestGroup group = new TestGroup();
		TestHasGroupElement validElement = new TestHasGroupElement(group);
		List<TestHasGroupElement> elements = Arrays.asList(validElement, null);
		assertThrows(IllegalArgumentException.class, () -> new SameGroupVector<>(elements));
	}

	@Test
	void testElementsOfDifferentGroupsThrows() {
		TestGroup group1 = new TestGroup();
		TestHasGroupElement first = new TestHasGroupElement(group1);
		TestGroup group2 = new TestGroup();
		TestHasGroupElement second = new TestHasGroupElement(group2);
		List<TestHasGroupElement> elements = Arrays.asList(first, second);
		assertThrows(IllegalArgumentException.class, () -> new SameGroupVector<>(elements));
	}

	@Test
	void testLengthReturnsElementsLength() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestHasGroupElement> elements =
				Stream
						.generate(() -> new TestHasGroupElement(group))
						.limit(n)
						.collect(Collectors.toList());
		assertEquals(n, new SameGroupVector<>(elements).size());
	}

	@Test
	void testGetElementReturnsElement() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestHasGroupElement> elements = Stream.generate(() -> new TestHasGroupElement(group)).limit(n).collect(Collectors.toList());
		int i = random.nextInt(n);
		assertEquals(elements.get(i), new SameGroupVector<>(elements).get(i));
	}

	@Test
	void testGetElementAboveRangeThrows() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestHasGroupElement> elements = Stream.generate(() -> new TestHasGroupElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestHasGroupElement, TestGroup> actor = new SameGroupVector<>(elements);
		assertThrows(IllegalArgumentException.class, () -> actor.get(n));
	}

	@Test
	void testGetElementBelowRangeThrows() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestHasGroupElement> elements = Stream.generate(() -> new TestHasGroupElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestHasGroupElement, TestGroup> actor = new SameGroupVector<>(elements);
		assertThrows(IllegalArgumentException.class, () -> actor.get(-1));
	}

	@Test
	void testGetGroupReturnsElementsGroup() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestHasGroupElement> elements = Stream.generate(() -> new TestHasGroupElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestHasGroupElement, TestGroup> actor = new SameGroupVector<>(elements);
		assertEquals(group, actor.getGroup());
	}

	@Test
	void givenElementsWhenGetElementsThenExpectedElements() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestHasGroupElement> elements = Stream.generate(() -> new TestHasGroupElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestHasGroupElement, TestGroup> actor = new SameGroupVector<>(elements);
		assertEquals(elements, actor.stream().collect(Collectors.toList()));
	}

	@Test
	void givenAPropertyHoldsForAnEmptyVector() {
		SameGroupVector<TestHasGroupElement, ?> empty = SameGroupVector.of();
		SecureRandom random = new SecureRandom();
		Function<TestHasGroupElement, ?> randomFunction = ignored -> random.nextInt();
		assertTrue(empty.allEqual(randomFunction));
	}

	@Test
	void threeElementsWithTheSamePropertyAreAllEqualAndDifferentPropertiesNotEqual() {
		TestGroup group = new TestGroup();
		TestValuedElement first = new TestValuedElement(BigInteger.valueOf(1), group);
		TestValuedElement second = new TestValuedElement(BigInteger.valueOf(2), group);
		TestValuedElement third = new TestValuedElement(BigInteger.valueOf(3), group);
		List<TestValuedElement> elements = Arrays.asList(first, second, third);
		SameGroupVector<TestValuedElement, TestGroup> vector = new SameGroupVector<>(elements);
		assertAll(() -> {
			assertFalse(vector.allEqual(TestValuedElement::getValue));
			assertTrue(vector.allEqual(TestValuedElement::getGroup));
		});
	}

	@Test
	void isEmptyReturnsTrueForEmptyVector() {
		List<TestHasGroupElement> elements = Collections.emptyList();
		SameGroupVector<TestHasGroupElement, TestGroup> vector = new SameGroupVector<>(elements);
		assertTrue(vector.isEmpty());
	}

	@Test
	void isEmptyReturnsFalseForNonEmptyVector() {
		TestGroup group = new TestGroup();
		List<TestHasGroupElement> elements = Collections.singletonList(new TestHasGroupElement(group));
		SameGroupVector<TestHasGroupElement, TestGroup> vector = new SameGroupVector<>(elements);
		assertFalse(vector.isEmpty());
	}

	@Test
	void appendWithInvalidParamsThrows() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(10) + 1;
		List<TestHasGroupElement> elements = Stream.generate(() -> new TestHasGroupElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestHasGroupElement, TestGroup> sameGroupVector = new SameGroupVector<>(elements);

		assertThrows(NullPointerException.class, () -> sameGroupVector.append(null));

		final TestHasGroupElement element = new TestHasGroupElement(new TestGroup());
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> sameGroupVector.append(element));
		assertEquals("The element to prepend must be in the same group.", illegalArgumentException.getMessage());
	}

	@RepeatedTest(10)
	void appendCorrectlyAppends() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(10) + 1;
		List<TestHasGroupElement> elements = Stream.generate(() -> new TestHasGroupElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestHasGroupElement, TestGroup> sameGroupVector = new SameGroupVector<>(elements);

		final TestHasGroupElement element = new TestHasGroupElement(group);
		final SameGroupVector<TestHasGroupElement, TestGroup> augmentedVector = sameGroupVector.append(element);

		assertEquals(sameGroupVector.size() + 1, augmentedVector.size());
		assertEquals(element, augmentedVector.get(n));
	}

	@Test
	void prependWithInvalidParamsThrows() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(10) + 1;
		List<TestHasGroupElement> elements = Stream.generate(() -> new TestHasGroupElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestHasGroupElement, TestGroup> sameGroupVector = new SameGroupVector<>(elements);

		assertThrows(NullPointerException.class, () -> sameGroupVector.prepend(null));

		final TestHasGroupElement element = new TestHasGroupElement(new TestGroup());
		final IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> sameGroupVector.prepend(element));
		assertEquals("The element to prepend must be in the same group.", illegalArgumentException.getMessage());
	}

	@RepeatedTest(10)
	void prependCorrectlyPrepends() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(10) + 1;
		List<TestHasGroupElement> elements = Stream.generate(() -> new TestHasGroupElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestHasGroupElement, TestGroup> sameGroupVector = new SameGroupVector<>(elements);

		final TestHasGroupElement element = new TestHasGroupElement(group);
		final SameGroupVector<TestHasGroupElement, TestGroup> augmentedVector = sameGroupVector.prepend(element);

		assertEquals(sameGroupVector.size() + 1, augmentedVector.size());
		assertEquals(element, augmentedVector.get(0));
	}

	@Test
	void toSameGroupVectorCorrectlyCollects() {
		int n = random.nextInt(10) + 1;
		TestGroup group = new TestGroup();
		List<TestHasGroupElement> elements = Stream.generate(() -> new TestHasGroupElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestHasGroupElement, TestGroup> actual = elements.stream().collect(SameGroupVector.toSameGroupVector());
		SameGroupVector<TestHasGroupElement, TestGroup> expected = new SameGroupVector<>(elements);

		assertEquals(expected, actual);
	}

	private static class TestValuedElement extends GroupElement<TestGroup> {
		protected TestValuedElement(BigInteger value, TestGroup group) {
			super(value, group);
		}
	}

	@Nested
	@DisplayName("Transforming a vector of ciphertext into a matrix of ciphertexts...")
	class ToCiphertextMatrixTest {

		private static final int BOUND_MATRIX_SIZE = 10;

		private int m;
		private int n;

		private TestGroup group;
		private SameGroupVector<TestHasGroupElement, TestGroup> sameGroupVector;

		@BeforeEach
		void setup() {
			m = random.nextInt(BOUND_MATRIX_SIZE) + 1;
			n = random.nextInt(BOUND_MATRIX_SIZE) + 1;

			group = new TestGroup();
			List<TestHasGroupElement> elements = Stream.generate(() -> new TestHasGroupElement(group)).limit((long) n * m)
					.collect(Collectors.toList());
			sameGroupVector = new SameGroupVector<>(elements);
		}

		@Test
		@DisplayName("with negative number of rows or columns throws IllegalArgumentException")
		void toCiphertextMatrixWithInvalidNumRowsOrColumns() {
			Exception exception = assertThrows(IllegalArgumentException.class, () -> sameGroupVector.toCiphertextMatrix(-m, n));
			assertEquals("The number of rows must be positive.", exception.getMessage());
			exception = assertThrows(IllegalArgumentException.class, () -> sameGroupVector.toCiphertextMatrix(m, -n));
			assertEquals("The number of columns must be positive.", exception.getMessage());
		}

		@Test
		@DisplayName("with incompatible decomposition into rows and columns throws an IllegalArgumentException")
		void toCiphertextMatrixWithWrongN() {
			Exception exception = assertThrows(IllegalArgumentException.class, () -> sameGroupVector.toCiphertextMatrix(m + 1, n));
			assertEquals("The vector of ciphertexts must be decomposable into m rows and n columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with valid input yields expected result")
		void toCiphertextMatrixTest() {
			SameGroupMatrix<TestHasGroupElement, TestGroup> ciphertextMatrix = sameGroupVector.toCiphertextMatrix(m, n);

			for (int i = 0; i < m; i++) {
				for (int j = 0; j < n; j++) {
					assertEquals(sameGroupVector.get(i + m * j), ciphertextMatrix.get(i, j));
				}
			}
		}
	}

	@Nested
	@DisplayName("Transforming a vector of exponents into a matrix of exponents...")
	class ToExponentMatrixTest {

		private static final int BOUND_MATRIX_SIZE = 10;

		private int m;
		private int n;

		private TestGroup group;
		private SameGroupVector<TestHasGroupElement, TestGroup> sameGroupVector;

		@BeforeEach
		void setup() {
			m = random.nextInt(BOUND_MATRIX_SIZE) + 1;
			n = random.nextInt(BOUND_MATRIX_SIZE) + 1;

			group = new TestGroup();
			List<TestHasGroupElement> elements = Stream.generate(() -> new TestHasGroupElement(group)).limit((long) n * m)
					.collect(Collectors.toList());
			sameGroupVector = new SameGroupVector<>(elements);
		}

		@Test
		@DisplayName("with negative number of rows or columns throws IllegalArgumentException")
		void toExponentMatrixWithInvalidNumRowsOrColumns() {
			Exception exception = assertThrows(IllegalArgumentException.class, () -> sameGroupVector.toExponentMatrix(-m, n));
			assertEquals("The number of rows must be positive.", exception.getMessage());
			exception = assertThrows(IllegalArgumentException.class, () -> sameGroupVector.toExponentMatrix(m, -n));
			assertEquals("The number of columns must be positive.", exception.getMessage());
		}

		@Test
		@DisplayName("with incompatible decomposition into rows and columns throws an IllegalArgumentException")
		void toExponentMatrixWithWrongN() {
			Exception exception = assertThrows(IllegalArgumentException.class, () -> sameGroupVector.toExponentMatrix(n + 1, m));
			assertEquals("The vector of exponents must be decomposable into n rows and m columns.", exception.getMessage());
		}

		@Test
		@DisplayName("with valid input yields expected result")
		void toExponentMatrixTest() {
			SameGroupMatrix<TestHasGroupElement, TestGroup> exponentMatrix = sameGroupVector.toExponentMatrix(n, m);

			for (int i = 0; i < n; i++) {
				for (int j = 0; j < m; j++) {
					assertEquals(sameGroupVector.get(m * i + j), exponentMatrix.get(i, j));
				}
			}
		}
	}
}