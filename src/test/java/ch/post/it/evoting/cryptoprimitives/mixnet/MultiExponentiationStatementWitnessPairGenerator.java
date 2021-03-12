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

import ch.post.it.evoting.cryptoprimitives.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
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
		GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix = this.elGamalGenerator.genRandomCiphertextMatrix(m, n, l);
		GroupMatrix<ZqElement, ZqGroup> AMatrix = zqGroupGenerator.genRandomZqElementMatrix(n, m);
		GroupVector<ZqElement, ZqGroup> rExponents = zqGroupGenerator.genRandomZqElementVector(m);
		ZqElement rhoExponents = zqGroupGenerator.genRandomZqElementMember();

		ElGamalMultiRecipientCiphertext computedC = argumentService.multiExponentiation(CMatrix, AMatrix, rhoExponents, m, l);
		GroupVector<GqElement, GqGroup> commitmentToA = CommitmentService.getCommitmentMatrix(
				AMatrix, rExponents, commitmentKey);
		MultiExponentiationStatement statement = new MultiExponentiationStatement(CMatrix, computedC, commitmentToA);
		MultiExponentiationWitness witness = new MultiExponentiationWitness(AMatrix, rExponents, rhoExponents);
		return new StatementWitnessPair(statement, witness);
	}
}
