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

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.mixnet.MultiExponentiationStatement;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupMatrix;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

public class TestMultiExponentiationStatementGenerator {
	private final GqGroupGenerator gqGroupGenerator;
	private final ElGamalGenerator elGamalGenerator;

	TestMultiExponentiationStatementGenerator(GqGroup gqGroup) {
		this.gqGroupGenerator = new GqGroupGenerator(gqGroup);
		this.elGamalGenerator = new ElGamalGenerator(gqGroup);
	}

	MultiExponentiationStatement genRandomStatement(int n, int m, int l) {
		GroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> CMatrix = elGamalGenerator.genRandomCiphertextMatrix(m, n, l);
		ElGamalMultiRecipientCiphertext C = elGamalGenerator.genRandomCiphertext(l);
		GroupVector<GqElement, GqGroup> cA = gqGroupGenerator.genRandomGqElementVector(m);
		return new MultiExponentiationStatement(CMatrix, C, cA);
	}
}
