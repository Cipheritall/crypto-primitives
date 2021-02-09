package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

class DiagonalProducts {

	private final ElGamalMultiRecipientPublicKey publicKey;

	DiagonalProducts(final ElGamalMultiRecipientPublicKey publicKey) {
		this.publicKey = publicKey;
	}

	/**
	 * Computes the products of the diagonals of a ciphertext matrix.
	 * <p>
	 * The ciphertexts and exponents matrix must comply with the following:
	 * <ul>
	 *     <li>The ciphertexts matrix must have as many columns as the exponents matrix has rows</li>
	 *     <li>The exponents matrix must have one more column than the ciphertexts matrix has rows</li>
	 *     <li>The exponents group must have the order of the ciphertexts group</li>
	 *     <li>The ciphertexts' phis must not be larger than the elements in the public key</li>
	 *     <li>The ciphertexts and public key must be part of the same group</li>
	 * </ul>
	 *
	 * @param ciphertexts C, the ciphertexts matrix.
	 * @param exponents   A, the exponents matrix.
	 * @return A {@link SameGroupVector} of size 2m.
	 */
	SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> getDiagonalProducts(
			final SameGroupMatrix<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts, final SameGroupMatrix<ZqElement, ZqGroup> exponents) {

		// Null checking.
		checkNotNull(ciphertexts);
		checkNotNull(exponents);

		// Empty matrices handling.
		checkArgument(!ciphertexts.isEmpty() && !exponents.isEmpty(), "The ciphertexts and exponents matrices can not be empty.");

		// Dimensions checking.
		checkArgument(ciphertexts.numColumns() == exponents.numRows(),
				"The ciphertexts matrix must have as many columns as the exponents matrix has rows.");
		checkArgument(ciphertexts.numRows() + 1 == exponents.numColumns(),
				"The exponents matrix must have one more column than the ciphertexts matrix has rows.");
		checkArgument(ciphertexts.get(0, 0).size() <= publicKey.size(),
				"There must be at least the same number of key elements than ciphertexts' phis.");
		checkArgument(ciphertexts.stream().map(ElGamalMultiRecipientCiphertext::size).distinct().count() <= 1,
				"All ciphertexts must have the same number of phis.");

		// Group checking.
		checkArgument(publicKey.getGroup().equals(ciphertexts.getGroup()), "The public key and ciphertexts matrices must be part of the same group.");
		checkArgument(ciphertexts.getGroup().getQ().equals(exponents.getGroup().getQ()),
				"The exponents group must have the order of the ciphertexts group.");

		// Algorithm.

		final int m = ciphertexts.numRows();
		final int l = ciphertexts.get(0, 0).size();
		final GqGroup gqGroup = publicKey.getGroup();
		final ZqGroup zqGroup = exponents.getGroup();
		final ElGamalMultiRecipientMessage ones = Stream.generate(() -> GqElement.create(BigInteger.ONE, gqGroup)).limit(l)
				.collect(Collectors.collectingAndThen(Collectors.toList(), ElGamalMultiRecipientMessage::new));

		// Corresponds to the dk of the specifications.
		final ElGamalMultiRecipientCiphertext ciphertextMultiplicationIdentity = ElGamalMultiRecipientCiphertext
				.getCiphertext(ones, ZqElement.create(BigInteger.ZERO, zqGroup), publicKey);

		// Compute the diagonal products D.
		return IntStream.range(0, 2 * m)
				.mapToObj(k -> {
					int lowerBound;
					int upperBound;
					if (k < m) {
						lowerBound = (m - k) - 1;
						upperBound = m;
					} else {
						lowerBound = 0;
						upperBound = 2 * m - k;
					}

					return IntStream.range(lowerBound, upperBound)
							.mapToObj(i -> {
								final int j = (k - m) + i + 1;
								final SameGroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertextRowI = ciphertexts.getRow(i);
								final SameGroupVector<ZqElement, ZqGroup> exponentsColumnJ = exponents.getColumn(j);
								return ElGamalMultiRecipientCiphertext.getCiphertextVectorExponentiation(ciphertextRowI, exponentsColumnJ);
							})
							.reduce(ciphertextMultiplicationIdentity, ElGamalMultiRecipientCiphertext::multiply);
				})
				.collect(Collectors.collectingAndThen(Collectors.toList(), SameGroupVector::new));
	}

}
