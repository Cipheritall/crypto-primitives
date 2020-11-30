/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

/**
 * A multi-recipient ElGamal key pair consisting of a public and a private key with N elements.
 *
 * <p>Instances of this class are immutable. </p>
 */
public class ElGamalMultiRecipientKeyPair {

	private final ElGamalMultiRecipientPublicKey publicKey;
	private final ElGamalMultiRecipientPrivateKey privateKey;

	private ElGamalMultiRecipientKeyPair(final ElGamalMultiRecipientPrivateKey privateKey, final ElGamalMultiRecipientPublicKey publicKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	/**
	 * Generates an ElGamalMultiRecipientKeyPair in the specified group and with the specified number of elements.
	 *
	 * @param group         The {@link GqGroup} in which to generate the public keys. Not null.
	 * @param numElements,  N, the number of elements that each key (the public key and the private key) should be composed of. This value must be
	 *                      greater than 0.
	 * @param randomService a service providing randomness. Not null.
	 */
	public static ElGamalMultiRecipientKeyPair genKeyPair(final GqGroup group, final int numElements, final RandomService randomService) {
		checkNotNull(randomService);
		checkNotNull(group);
		checkArgument(numElements > 0, "Cannot generate a ElGamalMultiRecipient key pair with %s elements.", numElements);

		GqElement generator = group.getGenerator();
		ZqGroup privateKeyGroup = ZqGroup.sameOrderAs(group);

		// Generate the private key as a list of random exponents
		List<ZqElement> privateKeyElements =
				Stream.generate(() -> randomService.genRandomExponent(privateKeyGroup))
						.limit(numElements)
						.collect(Collectors.toList());
		ElGamalMultiRecipientPrivateKey privateKey = new ElGamalMultiRecipientPrivateKey(privateKeyElements);

		// Calculate the public key from the private key previously generated
		List<GqElement> publicKeyElements = privateKeyElements.stream().map(generator::exponentiate).collect(Collectors.toList());
		ElGamalMultiRecipientPublicKey publicKey = new ElGamalMultiRecipientPublicKey(publicKeyElements);

		return new ElGamalMultiRecipientKeyPair(privateKey, publicKey);
	}

	public ElGamalMultiRecipientPublicKey getPublicKey() {
		return publicKey;
	}

	public ElGamalMultiRecipientPrivateKey getPrivateKey() {
		return privateKey;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ElGamalMultiRecipientKeyPair that = (ElGamalMultiRecipientKeyPair) o;
		return publicKey.equals(that.publicKey) && privateKey.equals(that.privateKey);
	}

	@Override
	public int hashCode() {
		return Objects.hash(publicKey, privateKey);
	}
}
