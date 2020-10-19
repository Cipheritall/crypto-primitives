package ch.post.it.evoting.cryptoprimitives.mixnet;

import java.util.List;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.random.Permutation;

/**
 * Represents the result of a re-encrypting shuffle operation. It contains the re-encrypted ciphertexts, the list of exponents used for re-encryption
 * and the permutation used for shuffling.
 *
 * Instances of this class are immutable.
 */
public class Shuffle {
	private final ImmutableList<ElGamalMultiRecipientCiphertext> ciphertexts;
	private final Permutation permutation;
	private final ImmutableList<ZqElement> reEncryptionExponents;

	Shuffle(final ImmutableList<ElGamalMultiRecipientCiphertext> ciphertexts,
			final Permutation permutation,
			final ImmutableList<ZqElement> reEncryptionExponents) {
		this.ciphertexts = ciphertexts;
		this.permutation = permutation;
		this.reEncryptionExponents = reEncryptionExponents;
	}

	List<ElGamalMultiRecipientCiphertext> getCiphertexts() {
		return this.ciphertexts;
	}

	Permutation getPermutation() {
		return permutation;
	}

	ImmutableList<ZqElement> getReEncryptionExponents() {
		return reEncryptionExponents;
	}
}
