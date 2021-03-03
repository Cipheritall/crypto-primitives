package ch.post.it.evoting.cryptoprimitives.elgamal;

public class ElGamalService implements ElGamal {
	@Override
	public ElGamalMultiRecipientMessage getMessage(ElGamalMultiRecipientCiphertext ciphertext, ElGamalMultiRecipientPrivateKey secretKey) {
		return ElGamalMultiRecipientMessage.getMessage(ciphertext, secretKey);
	}
}
