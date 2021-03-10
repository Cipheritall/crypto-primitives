/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.SameGroupVector.toSameGroupVector;
import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;

import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.Permutation;
import ch.post.it.evoting.cryptoprimitives.random.PermutationService;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ElGamalGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class ShuffleArgumentGenerator {

	private final GqGroup gqGroup;
	private final ZqGroupGenerator zqGroupGenerator;
	private final ElGamalGenerator elGamalGenerator;

	private final PermutationService permutationService;

	ShuffleArgumentGenerator(final GqGroup gqGroup) {
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
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator.genRandomCiphertextVector(N, l);
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = elGamalGenerator.genRandomCiphertextVector(N, l);

		return new ShuffleStatement(ciphertexts, shuffledCiphertexts);
	}

	/**
	 * Generates a valid {@link ShuffleStatement} - {@link ShuffleWitness} pair.
	 */
	ShuffleArgumentPair genShuffleArgumentPair(final int N, final int l, final ElGamalMultiRecipientPublicKey publicKey) {
		// Create a witness.
		final Permutation permutation = permutationService.genPermutation(N);
		final SameGroupVector<ZqElement, ZqGroup> randomness = zqGroupGenerator.genRandomZqElementVector(N);

		final ShuffleWitness shuffleWitness = new ShuffleWitness(permutation, randomness);

		// Create the corresponding statement.
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts = elGamalGenerator.genRandomCiphertextVector(N, l);

		final ElGamalMultiRecipientMessage ones = ElGamalMultiRecipientMessage.ones(gqGroup, l);
		final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> shuffledCiphertexts = IntStream.range(0, N)
				.mapToObj(i -> getCiphertext(ones, randomness.get(i), publicKey)
						.multiply(ciphertexts.get(permutation.get(i))))
				.collect(toSameGroupVector());

		final ShuffleStatement shuffleStatement = new ShuffleStatement(ciphertexts, shuffledCiphertexts);

		return new ShuffleArgumentPair(shuffleStatement, shuffleWitness);
	}

	static class ShuffleArgumentPair {

		private final ShuffleStatement shuffleStatement;
		private final ShuffleWitness shuffleWitness;

		ShuffleArgumentPair(ShuffleStatement shuffleStatement, ShuffleWitness shuffleWitness) {
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
