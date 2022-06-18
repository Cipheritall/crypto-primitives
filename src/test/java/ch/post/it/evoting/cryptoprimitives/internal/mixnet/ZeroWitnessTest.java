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

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.mixnet.ZeroWitness;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

@DisplayName("A ZeroWitness")
class ZeroWitnessTest {

	private static final SecureRandom secureRandom = new SecureRandom();

	private static ZqGroup zqGroup;
	private static ZqGroupGenerator zqGroupGenerator;

	private int n;
	private int m;
	private GroupMatrix<ZqElement, ZqGroup> matrixA;
	private GroupMatrix<ZqElement, ZqGroup> matrixB;
	private GroupVector<ZqElement, ZqGroup> exponentsR;
	private GroupVector<ZqElement, ZqGroup> exponentsS;

	@BeforeAll
	static void setUpAll() {
		zqGroup = GroupTestData.getZqGroup();
		zqGroupGenerator = new ZqGroupGenerator(zqGroup);
	}

	@BeforeEach
	void setUp() {
		n = secureRandom.nextInt(10) + 1;
		m = secureRandom.nextInt(10) + 1;

		matrixA = zqGroupGenerator.genRandomZqElementMatrix(n, m);
		matrixB = zqGroupGenerator.genRandomZqElementMatrix(n, m);
		exponentsR = zqGroupGenerator.genRandomZqElementVector(m);
		exponentsS = zqGroupGenerator.genRandomZqElementVector(m);
	}

	@Test
	@DisplayName("constructed with valid parameters works as expected")
	void construct() {
		final ZeroWitness zeroWitness = new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS);

		assertEquals(zqGroup, zeroWitness.get_A().getGroup());
		assertEquals(zqGroup, zeroWitness.get_B().getGroup());
		assertEquals(zqGroup, zeroWitness.get_r().getGroup());
		assertEquals(zqGroup, zeroWitness.get_s().getGroup());
	}

	@Test
	@DisplayName("constructed with any null parameter throws IllegalArgumentException")
	void constructNullParams() {
		final GroupVector<ZqElement, ZqGroup> emptyExponentsR = GroupVector.of();
		final GroupVector<ZqElement, ZqGroup> emptyExponentsS = GroupVector.of();

		assertAll(
				() -> assertThrows(NullPointerException.class, () -> new ZeroWitness(null, matrixB, exponentsR, exponentsS)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroWitness(matrixA, null, exponentsR, exponentsS)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroWitness(matrixA, matrixB, null, exponentsS)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroWitness(matrixA, matrixB, exponentsR, null))
		);
	}

	@Test
	@DisplayName("constructed with matrices of different size throws IllegalArgumentException")
	void constructDiffSizeMatrices() {
		final GroupMatrix<ZqElement, ZqGroup> additionalRowMatrix = zqGroupGenerator.genRandomZqElementMatrix(n + 1, m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(additionalRowMatrix, matrixB, exponentsR, exponentsS));
		assertEquals("The two matrices must have the same number of rows.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with exponents of different size throws IllegalArgumentException")
	void constructDiffSizeExponents() {
		final GroupVector<ZqElement, ZqGroup> additionalElemExponentsR = exponentsR.append(ZqElement.create(BigInteger.ONE, zqGroup));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, additionalElemExponentsR, exponentsS));
		assertEquals("The exponents vector must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with exponents of size not equal to number of matrices rows throws IllegalArgumentException")
	void constructSizeExponentsNotEqualMatricesRows() {
		final GroupVector<ZqElement, ZqGroup> additionalElemExponentsR = exponentsR.append(ZqElement.create(BigInteger.ONE, zqGroup));
		final GroupVector<ZqElement, ZqGroup> additionalElemExponentsS = exponentsS.append(ZqElement.create(BigInteger.ONE, zqGroup));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, additionalElemExponentsR, additionalElemExponentsS));
		assertEquals("The exponents vectors size must be the number of columns of the matrices.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with matrices with different number of columns throws IllegalArgumentException")
	void constructMatricesDiffColNumber() {
		final GroupVector<ZqElement, ZqGroup> newColumn = zqGroupGenerator.genRandomZqElementVector(n);
		final GroupMatrix<ZqElement, ZqGroup> additionalColMatrixA = matrixA.appendColumn(newColumn);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(additionalColMatrixA, matrixB, exponentsR, exponentsS));
		assertEquals("The two matrices must have the same number of columns.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with matrices from different group throws IllegalArgumentException")
	void constructMatricesDiffGroup() {
		// Get another group.
		final ZqGroup otherZqGroup = GroupTestData.getDifferentZqGroup(zqGroup);
		final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);

		final GroupMatrix<ZqElement, ZqGroup> otherZqGroupMatrix = otherZqGroupGenerator.genRandomZqElementMatrix(n, m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(otherZqGroupMatrix, matrixB, exponentsR, exponentsS));
		assertEquals("The matrices are not from the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with exponents from different group throws IllegalArgumentException")
	void constructExponentsDiffGroup() {
		// Get another group.
		final ZqGroup otherZqGroup = GroupTestData.getDifferentZqGroup(zqGroup);
		final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);

		final GroupVector<ZqElement, ZqGroup> otherZqGroupExponents = otherZqGroupGenerator.genRandomZqElementVector(m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, otherZqGroupExponents, exponentsS));
		assertEquals("The exponents are not from the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with matrices and exponents from different group throws IllegalArgumentException")
	void constructMatricesExponentsDiffGroup() {
		// Get another group.
		final ZqGroup otherZqGroup = GroupTestData.getDifferentZqGroup(zqGroup);
		final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);

		final GroupVector<ZqElement, ZqGroup> otherZqGroupExponentsR = otherZqGroupGenerator.genRandomZqElementVector(m);
		final GroupVector<ZqElement, ZqGroup> otherZqGroupExponentsS = otherZqGroupGenerator.genRandomZqElementVector(m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, otherZqGroupExponentsR, otherZqGroupExponentsS));
		assertEquals("The matrices and exponents are not from the same group.", exception.getMessage());
	}
}
