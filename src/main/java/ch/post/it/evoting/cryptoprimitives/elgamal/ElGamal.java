package ch.post.it.evoting.cryptoprimitives.elgamal;

public interface ElGamal {

	/**
	 * Decrypts a given ciphertext with the given secret key.
	 *
	 * @param ciphertext c,	the {@link ElGamalMultiRecipientCiphertext} to be decrypted
	 * @param secretKey  sk, the {@link ElGamalMultiRecipientPrivateKey} to be used for decrypting
	 * @return the decrypted plaintext message as {@link ElGamalMultiRecipientMessage}
	 */
	ElGamalMultiRecipientMessage getMessage(ElGamalMultiRecipientCiphertext ciphertext, ElGamalMultiRecipientPrivateKey secretKey);
}
