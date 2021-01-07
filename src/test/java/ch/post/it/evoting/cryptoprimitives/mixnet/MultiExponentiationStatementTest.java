/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
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
	private SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix;
	private ElGamalMultiRecipientCiphertext C;
	private SameGroupVector<GqElement, GqGroup> cA;

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

		MultiExponentiationStatementGenerator statementGenerator = new MultiExponentiationStatementGenerator(gqGroup);
		MultiExponentiationStatement statement = statementGenerator.genRandomStatement(n, m, l);
		this.CMatrix = statement.getCMatrix();
		this.C = statement.getC();
		this.cA = statement.getcA();
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
		SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> otherMatrix = otherGroupElGamalGenerator.genRandomCiphertextMatrix(m, n, l);
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
		SameGroupVector<GqElement, GqGroup> otherCommitmentVector = otherGqGroupGenerator.genRandomGqElementVector(m);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new MultiExponentiationStatement(CMatrix, C, otherCommitmentVector));
		assertEquals("The ciphertext matrix and the commitment must be from the same group.", exception.getMessage());
	}

	@Test
	void ciphertextMatrixRowSizeIsNotCommitmentVectorSizeThrows() {
		SameGroupVector<GqElement, GqGroup> longerCommitmentVector = gqGroupGenerator.genRandomGqElementVector(m + 1);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new MultiExponentiationStatement(CMatrix, C, longerCommitmentVector));
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