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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;
import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;

import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class TestShuffleArgumentGenerator {

	private final GqGroup gqGroup;
	private final ZqGroupGenerator zqGroupGenerator;
	private final ElGamalGenerator elGamalGenerator;

	private final PermutationService permutationService;

	TestShuffleArgumentGenerator(final GqGroup gqGroup) {
		this.gqGroup = gqGroup;
		final ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);
		this.zqGroupGenerator = new ZqGroupGenerator(zqGroup);
		this.elGamalGenerator = new ElGamalGenerator(gqGroup);

		this.permutationService = new PermutationService(new RandomService());
	}

	/**
	 * Generates a standalone {@link ShuffleStatement}. This statement does not match any witness as it just composed of (consistent) random values.
	 */
	ShuffleStatement genShuffleStatement(final int N, final int l) {
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator.genRandomCiphertextVector(N, l);
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = elGamalGenerator.genRandomCiphertextVector(N, l);

		return new ShuffleStatement(ciphertexts, shuffledCiphertexts);
	}

	/**
	 * Generates a valid {@link ShuffleStatement} - {@link ShuffleWitness} pair.
	 */
	ShuffleArgumentPair genShuffleArgumentPair(final int N, final int l, final ElGamalMultiRecipientPublicKey publicKey) {
		// Create a witness.
		final Permutation permutation = permutationService.genPermutation(N);
		final GroupVector<ZqElement, ZqGroup> randomness = zqGroupGenerator.genRandomZqElementVector(N);

		final ShuffleWitness shuffleWitness = new ShuffleWitness(permutation, randomness);

		// Create the corresponding statement.
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator.genRandomCiphertextVector(N, l);

		final ElGamalMultiRecipientMessage ones = ElGamalMultiRecipientMessage.ones(gqGroup, l);
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = IntStream.range(0, N)
				.mapToObj(i -> getCiphertext(ones, randomness.get(i), publicKey)
						.multiply(ciphertexts.get(permutation.get(i))))
				.collect(toGroupVector());

		final ShuffleStatement shuffleStatement = new ShuffleStatement(ciphertexts, shuffledCiphertexts);

		return new ShuffleArgumentPair(shuffleStatement, shuffleWitness);
	}

	static class ShuffleArgumentPair {

		private final ShuffleStatement shuffleStatement;
		private final ShuffleWitness shuffleWitness;

		ShuffleArgumentPair(final ShuffleStatement shuffleStatement, final ShuffleWitness shuffleWitness) {
			this.shuffleStatement = shuffleStatement;
			this.shuffleWitness = shuffleWitness;
		}

		public ShuffleStatement getStatement() {
			return shuffleStatement;
		}

		public ShuffleWitness getWitness() {
			return shuffleWitness;
		}
	}
}
