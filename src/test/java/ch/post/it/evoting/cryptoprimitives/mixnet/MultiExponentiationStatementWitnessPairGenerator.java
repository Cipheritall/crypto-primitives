/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

public class MultiExponentiationStatementWitnessPairGenerator {

	private final GqGroup gqGroup;
	private final ZqGroup zqGroup;
	private final ElGamalGenerator elGamalGenerator;
	private final ZqGroupGenerator zqGroupGenerator;
	private final MultiExponentiationArgumentService argumentService;
	private final CommitmentKey commitmentKey;

	MultiExponentiationStatementWitnessPairGenerator(GqGroup group, MultiExponentiationArgumentService argumentService, CommitmentKey commitmentKey) {
		this.gqGroup = group;
		this.zqGroup = ZqGroup.sameOrderAs(gqGroup);
		this.zqGroupGenerator = new ZqGroupGenerator(zqGroup);
		this.elGamalGenerator = new ElGamalGenerator(gqGroup);
		this.argumentService = argumentService;
		this.commitmentKey = commitmentKey;
	}

	static class StatementWitnessPair {
		private final MultiExponentiationStatement statement;
		private final MultiExponentiationWitness witness;

		StatementWitnessPair(MultiExponentiationStatement statement, MultiExponentiationWitness witness) {
			this.statement = statement;
			this.witness = witness;
		}

		public MultiExponentiationStatement getStatement() {
			return statement;
		}

		public MultiExponentiationWitness getWitness() {
			return witness;
		}
	}

	StatementWitnessPair genPair(int n, int m, int l) {
		SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix = this.elGamalGenerator.genRandomCiphertextMatrix(m, n, l);
		SameGroupMatrix<ZqElement, ZqGroup> AMatrix = zqGroupGenerator.genRandomZqElementMatrix(n, m);
		SameGroupVector<ZqElement, ZqGroup> rExponents = zqGroupGenerator.genRandomZqElementVector(m);
		ZqElement rhoExponents = zqGroupGenerator.genRandomZqElementMember();

		ElGamalMultiRecipientCiphertext computedC = argumentService.multiExponentiation(CMatrix, AMatrix, rhoExponents, m, l);
		SameGroupVector<GqElement, GqGroup> commitmentToA = CommitmentService.getCommitmentMatrix(
				AMatrix, rExponents, commitmentKey);
		MultiExponentiationStatement statement = new MultiExponentiationStatement(CMatrix, computedC, commitmentToA);
		MultiExponentiationWitness witness = new MultiExponentiationWitness(AMatrix, rExponents, rhoExponents);
		return new StatementWitnessPair(statement, witness);
	}
}
