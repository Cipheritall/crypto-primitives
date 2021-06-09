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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

class MultiExponentiationStatementTest extends TestGroupSetup {

	private static int UPPER_BOUND_TEST_SIZE = 10;
	private static ElGamalGenerator elGamalGenerator;
	private static ElGamalGenerator otherGroupElGamalGenerator;
	private int n;
	private int m;
	private int l;
	private GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix;
	private ElGamalMultiRecipientCiphertext C;
	private GroupVector<GqElement, GqGroup> cA;

	@BeforeAll
	static void setUpAll() {
		elGamalGenerator = new ElGamalGenerator(gqGroup);
		otherGroupElGamalGenerator = new ElGamalGenerator(otherGqGroup);
	}

	@BeforeEach
	void setUp() {
		n = secureRandom.nextInt(UPPER_BOUND_TEST_SIZE) + 1;
		m = secureRandom.nextInt(UPPER_BOUND_TEST_SIZE) + 1;
		l = secureRandom.nextInt(UPPER_BOUND_TEST_SIZE) + 1;

		TestMultiExponentiationStatementGenerator statementGenerator = new TestMultiExponentiationStatementGenerator(gqGroup);
		MultiExponentiationStatement statement = statementGenerator.genRandomStatement(n, m, l);
		this.CMatrix = statement.get_C_matrix();
		this.C = statement.get_C();
		this.cA = statement.get_c_A();
	}

	@Test
	void nullValuesAreNotPermitted() {
		assertAll(
				() -> assertThrows(NullPointerException.class, () -> new MultiExponentiationStatement(null, C, cA)),
				() -> assertThrows(NullPointerException.class, () -> new MultiExponentiationStatement(CMatrix, null, cA)),
				() -> assertThrows(NullPointerException.class, () -> new MultiExponentiationStatement(CMatrix, C, null))
		);
	}

	@Test
	void ciphertextAndCiphertextMatrixAreNotFromSameGroupThrows() {
		GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> otherMatrix = otherGroupElGamalGenerator.genRandomCiphertextMatrix(m, n, l);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new MultiExponentiationStatement(otherMatrix, C, cA));
		assertEquals("The ciphertext matrix and the ciphertext C must be from the same group.", exception.getMessage());
	}

	@Test
	void ciphertextAndCommitmentVectorAreNotFromSameGroupThrows() {
		ElGamalMultiRecipientCiphertext otherC = otherGroupElGamalGenerator.genRandomCiphertext(l);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new MultiExponentiationStatement(CMatrix, otherC, cA));
		assertEquals("The ciphertext matrix and the ciphertext C must be from the same group.", exception.getMessage());
	}

	@Test
	void ciphertextMatrixAndCommitmentVectorAreNotFromSameGroupThrows() {
		GroupVector<GqElement, GqGroup> otherCommitmentVector = otherGqGroupGenerator.genRandomGqElementVector(m);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new MultiExponentiationStatement(CMatrix, C, otherCommitmentVector));
		assertEquals("The ciphertext matrix and the commitment must be from the same group.", exception.getMessage());
	}

	@Test
	void ciphertextMatrixRowSizeIsNotCommitmentVectorSizeThrows() {
		GroupVector<GqElement, GqGroup> longerCommitmentVector = gqGroupGenerator.genRandomGqElementVector(m + 1);
		Exception exception = assertThrows(IllegalArgumentException.class,
				() -> new MultiExponentiationStatement(CMatrix, C, longerCommitmentVector));
		assertEquals("The commitment must be the same size as the number of rows of the ciphertext matrix.", exception.getMessage());
	}

	@Test
	void emptyMatrixDoesNotThrow() {
		CMatrix = elGamalGenerator.genRandomCiphertextMatrix(0, 0, l);
		C = elGamalGenerator.genRandomCiphertext(l);
		cA = gqGroupGenerator.genRandomGqElementVector(0);
		assertDoesNotThrow(() -> new MultiExponentiationStatement(CMatrix, C, cA));
	}
}
