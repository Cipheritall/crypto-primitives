/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

public class MultiExponentiationStatementGenerator {
	private final GqGroupGenerator gqGroupGenerator;
	private final ElGamalGenerator elGamalGenerator;

	MultiExponentiationStatementGenerator(GqGroup gqGroup) {
		this.gqGroupGenerator = new GqGroupGenerator(gqGroup);
		this.elGamalGenerator = new ElGamalGenerator(gqGroup);
	}

	MultiExponentiationStatement genRandomStatement(int n, int m, int l) {
		SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix = elGamalGenerator.genRandomCiphertextMatrix(m, n, l);
		ElGamalMultiRecipientCiphertext C = elGamalGenerator.genRandomCiphertext(l);
		SameGroupVector<GqElement, GqGroup> cA = gqGroupGenerator.genRandomGqElementVector(m);
		return new MultiExponentiationStatement(CMatrix, C, cA);
	}
}
