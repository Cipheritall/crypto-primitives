package ch.post.it.evoting.cryptoprimitives.mixnet;

import java.util.List;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.random.Permutation;

/**
 * Represents the result of a re-encrypting shuffle operation. It contains the re-encrypted ciphertexts, the list of exponents used for re-encryption
 * and the permutation used for shuffling.
 */
public class Shuffle {
	private final ImmutableList<ElGamalMultiRecipientCiphertext> ciphertexts;
	private final Permutation permutation;
	private final List<ZqElement> reEncryptionExponents;

	Shuffle(final ImmutableList<ElGamalMultiRecipientCiphertext> ciphertexts,
			final Permutation permutation,
			final List<ZqElement> reEncryptionExponents) {
		this.ciphertexts = ciphertexts;
		this.permutation = permutation;
		this.reEncryptionExponents = reEncryptionExponents;
	}

	public List<ElGamalMultiRecipientCiphertext> getCiphertexts() {
		return this.ciphertexts;
	}

	public Permutation getPermutation() {
		return permutation;
	}

	public List<ZqElement> getReEncryptionExponents() {
		return reEncryptionExponents;
	}
}
