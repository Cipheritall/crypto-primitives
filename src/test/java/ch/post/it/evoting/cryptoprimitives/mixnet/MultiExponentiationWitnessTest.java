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

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

class MultiExponentiationWitnessTest extends TestGroupSetup {

	private static final int UPPER_BOUND_TEST_SIZE = 10;

	private int n;
	private int m;
	private SameGroupMatrix<ZqElement, ZqGroup> matrixA;
	private SameGroupVector<ZqElement, ZqGroup> exponentsR;
	private ZqElement exponentsRho;

	@BeforeEach
	void setUp() {
		n = secureRandom.nextInt(UPPER_BOUND_TEST_SIZE) + 1;
		m = secureRandom.nextInt(UPPER_BOUND_TEST_SIZE) + 1;

		MultiExponentiationWitnessGenerator witnessGenerator = new MultiExponentiationWitnessGenerator(zqGroup);
		MultiExponentiationWitness witness = witnessGenerator.genRandomWitness(n, m);
		matrixA = witness.getA();
		exponentsR = witness.getR();
		exponentsRho = witness.getRho();
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
	void testThatEmptyMatrixDoesNotThrow(){
		SameGroupMatrix<ZqElement, ZqGroup> emptyMatrix = zqGroupGenerator.genRandomZqElementMatrix(0, 0);
		SameGroupVector<ZqElement, ZqGroup> emptyExponents = zqGroupGenerator.genRandomZqElementVector(0);
		assertDoesNotThrow(() -> new MultiExponentiationWitness(emptyMatrix, emptyExponents, exponentsRho));
	}

	@Test
	void testThatExponentsOfDifferentSizeThanMatrixColumnsThrows(){
		SameGroupVector<ZqElement, ZqGroup> differentSizeExponents = zqGroupGenerator.genRandomZqElementVector(m + 1);
		Exception exception =
				assertThrows(IllegalArgumentException.class, () -> new MultiExponentiationWitness(matrixA, differentSizeExponents, exponentsRho));
		assertEquals("The matrix A number of columns must equals the number of exponents.", exception.getMessage());
	}

	@Test
	void testThatMatrixAndExponentsOfDifferentGroupsThrows(){
		SameGroupMatrix<ZqElement, ZqGroup> otherMatrix = otherZqGroupGenerator.genRandomZqElementMatrix(n, m);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new MultiExponentiationWitness(otherMatrix, exponentsR, exponentsRho));
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
		SameGroupVector<ZqElement, ZqGroup> otherR = otherZqGroupGenerator.genRandomZqElementVector(m);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new MultiExponentiationWitness(matrixA, otherR, exponentsRho));
		assertEquals("The matrix A and the exponents r must belong to the same group.", exception.getMessage());
	}
}
