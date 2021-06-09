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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

class MultiExponentiationWitnessTest extends TestGroupSetup {

	private static final int UPPER_BOUND_TEST_SIZE = 10;

	private int n;
	private int m;
	private GroupMatrix<ZqElement, ZqGroup> matrixA;
	private GroupVector<ZqElement, ZqGroup> exponentsR;
	private ZqElement exponentsRho;

	@BeforeEach
	void setUp() {
		n = secureRandom.nextInt(UPPER_BOUND_TEST_SIZE) + 1;
		m = secureRandom.nextInt(UPPER_BOUND_TEST_SIZE) + 1;

		TestMultiExponentiationWitnessGenerator witnessGenerator = new TestMultiExponentiationWitnessGenerator(zqGroup);
		MultiExponentiationWitness witness = witnessGenerator.genRandomWitness(n, m);
		matrixA = witness.get_A();
		exponentsR = witness.get_r();
		exponentsRho = witness.get_rho();
	}

	@Test
	void nullsAreNotValidParameters() {
		assertAll(
				() -> assertThrows(NullPointerException.class, () -> new MultiExponentiationWitness(null, exponentsR, exponentsRho)),
				() -> assertThrows(NullPointerException.class, () -> new MultiExponentiationWitness(matrixA, null, exponentsRho)),
				() -> assertThrows(NullPointerException.class, () -> new MultiExponentiationWitness(matrixA, exponentsR, null))
		);
	}

	@Test
	void testThatEmptyMatrixDoesNotThrow() {
		GroupMatrix<ZqElement, ZqGroup> emptyMatrix = zqGroupGenerator.genRandomZqElementMatrix(0, 0);
		GroupVector<ZqElement, ZqGroup> emptyExponents = zqGroupGenerator.genRandomZqElementVector(0);
		assertDoesNotThrow(() -> new MultiExponentiationWitness(emptyMatrix, emptyExponents, exponentsRho));
	}

	@Test
	void testThatExponentsOfDifferentSizeThanMatrixColumnsThrows() {
		GroupVector<ZqElement, ZqGroup> differentSizeExponents = zqGroupGenerator.genRandomZqElementVector(m + 1);
		Exception exception =
				assertThrows(IllegalArgumentException.class, () -> new MultiExponentiationWitness(matrixA, differentSizeExponents, exponentsRho));
		assertEquals("The matrix A number of columns must equals the number of exponents.", exception.getMessage());
	}

	@Test
	void testThatMatrixAndExponentsOfDifferentGroupsThrows() {
		GroupMatrix<ZqElement, ZqGroup> otherMatrix = otherZqGroupGenerator.genRandomZqElementMatrix(n, m);
		Exception exception = assertThrows(IllegalArgumentException.class,
				() -> new MultiExponentiationWitness(otherMatrix, exponentsR, exponentsRho));
		assertEquals("The matrix A and the exponents r must belong to the same group.", exception.getMessage());
	}

	@Test
	void testThatMatrixAndExponentRhoOfDifferentGroupsThrows(){
		ZqElement otherRho = otherZqGroupGenerator.genRandomZqElementMember();
		Exception exception =
				assertThrows(IllegalArgumentException.class, () -> new MultiExponentiationWitness(matrixA, exponentsR, otherRho));
		assertEquals("The matrix A and the exponent ρ must belong to the same group", exception.getMessage());
	}

	@Test
	void testThatExponentsAndRhoOfDifferentGroupsThrows() {
		GroupVector<ZqElement, ZqGroup> otherR = otherZqGroupGenerator.genRandomZqElementVector(m);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new MultiExponentiationWitness(matrixA, otherR, exponentsRho));
		assertEquals("The matrix A and the exponents r must belong to the same group.", exception.getMessage());
	}
}
