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

import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestHasGroupElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.math.TestGroup;

class SameGroupVectorTest {

	static SecureRandom random = new SecureRandom();

	@Test
	void testNullElementsThrows() {
		assertThrows(NullPointerException.class, () -> new SameGroupVector<TestHasGroupElement, TestGroup>(null));
	}

	@Test
	void testEmptyElementsDoesNotThrow() {
		SameGroupVector<TestHasGroupElement, TestGroup> vector = new SameGroupVector<>(Collections.emptyList());
		assertEquals(0, vector.size());
	}

	@Test
	void testGroupOfEmptyVectorThrows() {
		SameGroupVector<TestHasGroupElement, TestGroup> vector = new SameGroupVector<>(Collections.emptyList());
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
		SameGroupVector<TestHasGroupElement, ?> empty = new SameGroupVector<>(Collections.emptyList());
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
		assertAll ( () -> {
			assertFalse(vector.allEqual(TestValuedElement::getValue));
			assertTrue(vector.allEqual(TestValuedElement::getGroup));
		});
	}

	private static class TestValuedElement extends GroupElement<TestGroup> {
		protected TestValuedElement(BigInteger value, TestGroup group) {
			super(value, group);
		}
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
}