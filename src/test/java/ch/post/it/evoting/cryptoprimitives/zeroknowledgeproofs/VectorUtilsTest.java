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
package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.VectorUtils.vectorAddition;
import static ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.VectorUtils.vectorExponentiation;
import static ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.VectorUtils.vectorMultiplication;
import static ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.VectorUtils.vectorScalarMultiplication;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.test.tools.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

class VectorUtilsTest extends TestGroupSetup {

	private static final int MAX_LENGTH = 10;
	private static final SecureRandom random = new SecureRandom();

	@Nested
	@DisplayName("vector addition with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VectorAddition {

		private int vectorSize;
		private GroupVector<ZqElement, ZqGroup> firstVector;
		private GroupVector<ZqElement, ZqGroup> secondVector;

		@BeforeEach
		void setUp() {
			vectorSize = random.nextInt(MAX_LENGTH) + 1;
			firstVector = zqGroupGenerator.genRandomZqElementVector(vectorSize);
			secondVector = zqGroupGenerator.genRandomZqElementVector(vectorSize);
		}

		@Test
		@DisplayName("valid parameters gives valid vector")
		void validParams() {
			final GroupVector<ZqElement, ZqGroup> sum = vectorAddition(firstVector, secondVector);

			assertEquals(vectorSize, sum.size());
			assertEquals(firstVector.getGroup(), sum.getGroup());
		}

		@Test
		@DisplayName("any null parameter throws NullPointerException")
		void nullParams() {
			assertThrows(NullPointerException.class, () -> vectorAddition(null, secondVector));
			assertThrows(NullPointerException.class, () -> vectorAddition(firstVector, null));
		}

		@Test
		@DisplayName("vectors of different sizes throws IllegalArgumentException")
		void differentSizes() {
			final GroupVector<ZqElement, ZqGroup> tooLongVector = zqGroupGenerator.genRandomZqElementVector(vectorSize + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> vectorAddition(tooLongVector, secondVector));
			assertEquals("The vectors to be added must have the same size.", exception.getMessage());
		}

		@Test
		@DisplayName("vectors of different groups throws IllegalArgumentException")
		void differentGroups() {
			final GroupVector<ZqElement, ZqGroup> diffGroupVector = otherZqGroupGenerator.genRandomZqElementVector(vectorSize);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> vectorAddition(diffGroupVector, secondVector));
			assertEquals("Both vectors must have the same group.", exception.getMessage());
		}

		Stream<Arguments> additionArgumentsProvider() {
			final BigInteger q = BigInteger.valueOf(5);
			final ZqGroup zqGroup = new ZqGroup(q);

			final GroupVector<ZqElement, ZqGroup> firstVector = GroupVector.of(ZqElement.create(1, zqGroup), ZqElement.create(4, zqGroup));
			final GroupVector<ZqElement, ZqGroup> secondVector = GroupVector.of(ZqElement.create(3, zqGroup), ZqElement.create(2, zqGroup));
			final GroupVector<ZqElement, ZqGroup> zeroVector = GroupVector.of(ZqElement.create(0, zqGroup), ZqElement.create(0, zqGroup));
			final GroupVector<ZqElement, ZqGroup> firstVectorNegated = firstVector.stream()
					.map(ZqElement::negate)
					.collect(toGroupVector());

			final GroupVector<ZqElement, ZqGroup> expected = GroupVector.of(ZqElement.create(4, zqGroup), ZqElement.create(1, zqGroup));

			return Stream.of(
					arguments(firstVector, secondVector, expected),
					arguments(firstVector, zeroVector, firstVector),
					arguments(firstVector, firstVectorNegated, zeroVector)
			);
		}

		@ParameterizedTest
		@MethodSource("additionArgumentsProvider")
		@DisplayName("specific values gives expected vector addition")
		void specificValues(final GroupVector<ZqElement, ZqGroup> firstVector, final GroupVector<ZqElement, ZqGroup> secondVector,
				final GroupVector<ZqElement, ZqGroup> expected) {

			final GroupVector<ZqElement, ZqGroup> addition = vectorAddition(firstVector, secondVector);

			assertEquals(expected, addition);
		}

	}

	@Nested
	@DisplayName("vector multiply with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VectorMultiplication {

		private int vectorSize;
		private GroupVector<GqElement, GqGroup> firstVector;
		private GroupVector<GqElement, GqGroup> secondVector;

		@BeforeEach
		void setUp() {
			vectorSize = random.nextInt(MAX_LENGTH) + 1;
			firstVector = gqGroupGenerator.genRandomGqElementVector(vectorSize);
			secondVector = gqGroupGenerator.genRandomGqElementVector(vectorSize);
		}

		@Test
		@DisplayName("valid parameters gives valid vector")
		void validParams() {
			final GroupVector<GqElement, GqGroup> product = vectorMultiplication(firstVector, secondVector);

			assertEquals(vectorSize, product.size());
			assertEquals(firstVector.getGroup(), product.getGroup());
		}

		@Test
		@DisplayName("any null parameter throws NullPointerException")
		void nullParams() {
			assertThrows(NullPointerException.class, () -> vectorMultiplication(null, secondVector));
			assertThrows(NullPointerException.class, () -> vectorMultiplication(firstVector, null));
		}

		@Test
		@DisplayName("vectors of different sizes throws IllegalArgumentException")
		void differentSizes() {
			final GroupVector<GqElement, GqGroup> tooLongVector = gqGroupGenerator.genRandomGqElementVector(vectorSize + 1);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> vectorMultiplication(tooLongVector, secondVector));
			assertEquals("The vectors to be multiplied must have the same size.", exception.getMessage());
		}

		@Test
		@DisplayName("vectors of different groups throws IllegalArgumentException")
		void differentGroups() {
			final GroupVector<GqElement, GqGroup> diffGroupVector = otherGqGroupGenerator.genRandomGqElementVector(vectorSize);

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> vectorMultiplication(diffGroupVector, secondVector));
			assertEquals("Both vectors must have the same group.", exception.getMessage());
		}

		@Test
		@DisplayName("specific values gives expected vector multiplication")
		void specificValues() {

			final BigInteger p = BigInteger.valueOf(11);
			final BigInteger q = BigInteger.valueOf(5);
			final BigInteger g = BigInteger.valueOf(3);

			final GqGroup gqGroup = new GqGroup(p, q, g);

			final GroupVector<GqElement, GqGroup> firstVector = GroupVector.of(GqElementFactory.fromValue(BigInteger.ONE, gqGroup),
					GqElementFactory.fromValue(BigInteger.valueOf(4), gqGroup));
			final GroupVector<GqElement, GqGroup> secondVector = GroupVector.of(GqElementFactory.fromValue(BigInteger.valueOf(3), gqGroup),
					GqElementFactory.fromValue(BigInteger.valueOf(4), gqGroup));
			final GroupVector<GqElement, GqGroup> oneVector = GroupVector.of(GqElementFactory.fromValue(BigInteger.ONE, gqGroup),
					GqElementFactory.fromValue(BigInteger.ONE, gqGroup));
			final GroupVector<GqElement, GqGroup> firstVectorInverted = firstVector.stream()
					.map(GqElement::invert)
					.collect(toGroupVector());

			final GroupVector<GqElement, GqGroup> expected = GroupVector.of(GqElementFactory.fromValue(BigInteger.valueOf(3), gqGroup),
					GqElementFactory.fromValue(BigInteger.valueOf(5), gqGroup));

			final GroupVector<GqElement, GqGroup> firstVector_multiply_secondVector = vectorMultiplication(firstVector, secondVector);
			final GroupVector<GqElement, GqGroup> firstVector_multiply_oneVector = vectorMultiplication(firstVector, oneVector);
			final GroupVector<GqElement, GqGroup> firstVector_multiply_firstVectorInverted = vectorMultiplication(firstVector, firstVectorInverted);
			final GroupVector<GqElement, GqGroup> oneVector_multiply_oneVector = vectorMultiplication(oneVector, oneVector);

			assertEquals(firstVector_multiply_secondVector, expected);
			assertEquals(firstVector_multiply_oneVector, firstVector);
			assertEquals(firstVector_multiply_firstVectorInverted, oneVector);
			assertEquals(oneVector_multiply_oneVector, oneVector);
		}

	}

	@Nested
	@DisplayName("vector exponentiate with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VectorExponentiate {

		private int vectorSize;
		private GroupVector<GqElement, GqGroup> vector;
		private ZqElement exponent;

		@BeforeEach
		void setUp() {
			vectorSize = random.nextInt(MAX_LENGTH) + 1;
			vector = gqGroupGenerator.genRandomGqElementVector(vectorSize);
			exponent = zqGroupGenerator.genRandomZqElementMember();
		}

		@Test
		@DisplayName("valid parameters gives valid vector")
		void validParams() {
			final GroupVector<GqElement, GqGroup> product = vectorExponentiation(vector, exponent);

			assertEquals(vectorSize, product.size());
			assertEquals(vector.getGroup(), product.getGroup());
		}

		@Test
		@DisplayName("any null parameter throws NullPointerException")
		void nullParams() {
			assertThrows(NullPointerException.class, () -> vectorExponentiation(vector, null));
			assertThrows(NullPointerException.class, () -> vectorExponentiation(null, exponent));
		}

		Stream<Arguments> exponentiateArgumentsProvider() {
			final BigInteger p = BigInteger.valueOf(11);
			final BigInteger q = BigInteger.valueOf(5);
			final BigInteger g = BigInteger.valueOf(3);

			final GqGroup gqGroup = new GqGroup(p, q, g);

			final ZqElement oneExponent = ZqElement.create(BigInteger.ONE, ZqGroup.sameOrderAs(gqGroup));
			final ZqElement zeroExponent = ZqElement.create(BigInteger.ZERO, ZqGroup.sameOrderAs(gqGroup));

			final GroupVector<GqElement, GqGroup> firstVector = GroupVector.of(GqElementFactory.fromValue(BigInteger.ONE, gqGroup),
					GqElementFactory.fromValue(BigInteger.valueOf(4), gqGroup));
			final ZqElement fourExponent = ZqElement.create(BigInteger.valueOf(4), ZqGroup.sameOrderAs(gqGroup));
			final GroupVector<GqElement, GqGroup> oneVector = GroupVector.of(GqElementFactory.fromValue(BigInteger.ONE, gqGroup),
					GqElementFactory.fromValue(BigInteger.ONE, gqGroup));

			final GroupVector<GqElement, GqGroup> expected = GroupVector.of(
					GqElementFactory.fromValue(BigInteger.valueOf(1), gqGroup),
					GqElementFactory.fromValue(BigInteger.valueOf(3), gqGroup));

			return Stream.of(
					arguments(firstVector, fourExponent, expected),
					arguments(firstVector, oneExponent, firstVector),
					arguments(firstVector, zeroExponent, oneVector)
			);
		}

		@ParameterizedTest
		@MethodSource("exponentiateArgumentsProvider")
		@DisplayName("specific values gives expected vector exponentation")
		void specificValues(final GroupVector<GqElement, GqGroup> vector, final ZqElement exponent,
				final GroupVector<GqElement, GqGroup> expected) {

			final GroupVector<GqElement, GqGroup> exponentiate = vectorExponentiation(vector, exponent);
			assertEquals(expected, exponentiate);
		}

	}

	@Nested
	@DisplayName("vector scalar multiplication with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VectorScalarMultiplication {

		private int vectorSize;
		private ZqElement scalar;
		private GroupVector<ZqElement, ZqGroup> vector;

		@BeforeEach
		void setUp() {
			vectorSize = random.nextInt(MAX_LENGTH) + 1;
			scalar = zqGroupGenerator.genRandomZqElementMember();
			vector = zqGroupGenerator.genRandomZqElementVector(vectorSize);
		}

		@Test
		@DisplayName("valid params gives valid multiplication")
		void validParams() {
			final GroupVector<ZqElement, ZqGroup> product = vectorScalarMultiplication(scalar, vector);

			assertEquals(vectorSize, product.size());
			assertEquals(vector.getGroup(), product.getGroup());
		}

		@Test
		@DisplayName("any null parameter throws NullPointerException")
		void nullParams() {
			assertThrows(NullPointerException.class, () -> vectorScalarMultiplication(null, vector));
			assertThrows(NullPointerException.class, () -> vectorScalarMultiplication(scalar, null));
		}

		@Test
		@DisplayName("scalar of different group throws IllegalArgumentException")
		void differentGroupScalar() {
			final ZqElement differentGroupScalar = otherZqGroupGenerator.genRandomZqElementMember();

			final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
					() -> vectorScalarMultiplication(differentGroupScalar, vector));
			assertEquals("The scalar must be of the same group than the vector.", exception.getMessage());
		}

		Stream<Arguments> multiplicationArgumentsProvider() {
			final BigInteger q = BigInteger.valueOf(5);
			final ZqGroup zqGroup = new ZqGroup(q);

			final ZqElement scalar = ZqElement.create(3, zqGroup);
			final ZqElement zeroScalar = ZqElement.create(0, zqGroup);
			final ZqElement oneScalar = ZqElement.create(1, zqGroup);
			final GroupVector<ZqElement, ZqGroup> vector = GroupVector.of(ZqElement.create(1, zqGroup), ZqElement.create(2, zqGroup));
			final GroupVector<ZqElement, ZqGroup> zeroVector = GroupVector.of(ZqElement.create(0, zqGroup), ZqElement.create(0, zqGroup));

			final GroupVector<ZqElement, ZqGroup> expected = GroupVector.of(ZqElement.create(3, zqGroup), ZqElement.create(1, zqGroup));

			return Stream.of(
					arguments(scalar, vector, expected),
					arguments(zeroScalar, vector, zeroVector),
					arguments(oneScalar, vector, vector)
			);
		}

		@ParameterizedTest
		@MethodSource("multiplicationArgumentsProvider")
		@DisplayName("specific values gives expected vector scalar multiplication")
		void specificValues(final ZqElement scalar, final GroupVector<ZqElement, ZqGroup> vector, final GroupVector<ZqElement, ZqGroup> expected) {
			assertEquals(expected, vectorScalarMultiplication(scalar, vector));
		}

	}
}