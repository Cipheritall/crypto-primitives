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

import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;

public class VerifiableShuffleGenerator {

	private final GqGroup group;

	public VerifiableShuffleGenerator(GqGroup group) {
		this.group = group;
	}

	public VerifiableShuffle genVerifiableShuffle(int numCiphertexts, int ciphertextSize) {
		final int[] matrixDimensions = MatrixUtils.getMatrixDimensions(numCiphertexts);
		final int m = matrixDimensions[0];
		final int n = matrixDimensions[1];

		ElGamalGenerator elGamalGenerator = new ElGamalGenerator(group);
		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator
				.genRandomCiphertextVector(numCiphertexts, ciphertextSize);
		ShuffleArgument shuffleArgument = new TestArgumentGenerator(group).genShuffleArgument(m, n, ciphertextSize);
		return new VerifiableShuffle(ciphertexts, shuffleArgument);
	}
}
