/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

import org.junit.jupiter.api.Test;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.math.StreamlinedGroupElement;
import ch.post.it.evoting.cryptoprimitives.math.StreamlinedMathematicalGroup;

class SameGroupVectorTest {

	static SecureRandom random = new SecureRandom();

	@Test
	void testNullElementsThrows() {
		assertThrows(NullPointerException.class, () -> new SameGroupVector<TestElement, TestGroup>(null));
	}

	@Test
	void testEmptyElementsThrows() {
		List<TestElement> elements = Collections.emptyList();
		assertThrows(IllegalArgumentException.class, () -> new SameGroupVector<>(elements));
	}

	@Test
	void testElementsWithNullThrows() {
		List<TestElement> elements = new ArrayList<>(Collections.emptyList());
		elements.add(null);
		assertThrows(IllegalArgumentException.class, () -> new SameGroupVector<>(elements));
	}

	@Test
	void testElementsWithValueAndNullThrows() {
		TestGroup group = new TestGroup();
		TestElement validElement = new TestElement(group);
		List<TestElement> elements = Arrays.asList(validElement, null);
		assertThrows(IllegalArgumentException.class, () -> new SameGroupVector<>(elements));
	}

	@Test
	void testElementsOfDifferentGroupsThrows() {
		TestGroup group1 = new TestGroup();
		TestElement first = new TestElement(group1);
		TestGroup group2 = new TestGroup();
		TestElement second = new TestElement(group2);
		List<TestElement> elements = Arrays.asList(first, second);
		assertThrows(IllegalArgumentException.class, () -> new SameGroupVector<>(elements));
	}

	@Test
	void testLengthReturnsElementsLength() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestElement> elements =
				Stream
						.generate(() -> new TestElement(group))
						.limit(n)
						.collect(Collectors.toList());
		assertEquals(n, new SameGroupVector<>(elements).length());
	}

	@Test
	void testGetElementReturnsElement() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestElement> elements = Stream.generate(() -> new TestElement(group)).limit(n).collect(Collectors.toList());
		int i = random.nextInt(n);
		assertEquals(elements.get(i), new SameGroupVector<>(elements).get(i));
	}

	@Test
	void testGetElementAboveRangeThrows() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestElement> elements = Stream.generate(() -> new TestElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestElement, TestGroup> actor = new SameGroupVector<>(elements);
		assertThrows(IllegalArgumentException.class, () -> actor.get(n));
	}

	@Test
	void testGetElementBelowRangeThrows() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestElement> elements = Stream.generate(() -> new TestElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestElement, TestGroup> actor = new SameGroupVector<>(elements);
		assertThrows(IllegalArgumentException.class, () -> actor.get(-1));
	}

	@Test
	void testGetGroupReturnsElementsGroup() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestElement> elements = Stream.generate(() -> new TestElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestElement, TestGroup> actor = new SameGroupVector<>(elements);
		assertEquals(group, actor.getGroup());
	}

	@Test
	void givenElementsWhenGetElementsThenExpectedElements() {
		TestGroup group = new TestGroup();
		int n = random.nextInt(100) + 1;
		List<TestElement> elements = Stream.generate(() -> new TestElement(group)).limit(n).collect(Collectors.toList());
		SameGroupVector<TestElement, TestGroup> actor = new SameGroupVector<>(elements);
		assertEquals(elements, actor.toList());
	}

	@Test
	void getKeysReturnsImmutableList() {
		TestGroup group = new TestGroup();
		TestElement element = new TestElement(group);
		SameGroupVector<TestElement, TestGroup> actor = new SameGroupVector<>(Collections.singletonList(element));
		assertTrue(actor.toList() instanceof ImmutableList);
	}

	private static class TestElement extends StreamlinedGroupElement<TestGroup> {
		//Create a TestElement with a random value with the given group
		private TestElement(TestGroup group) {
			super(BigInteger.valueOf(random.nextLong()), group);
		}

		private TestElement(BigInteger value, TestGroup group) {
			super(value, group);
		}

		@Override
		public BigInteger getValue() {
			throw new UnsupportedOperationException();
		}
	}

	private static class TestGroup implements StreamlinedMathematicalGroup<TestGroup> {
		@Override
		public boolean isGroupMember(BigInteger value) {
			return true;
		}

		@Override
		public TestElement getIdentity() {
			throw new UnsupportedOperationException();
		}

		@Override
		public BigInteger getQ() {
			throw new UnsupportedOperationException();
		}
	}
}
