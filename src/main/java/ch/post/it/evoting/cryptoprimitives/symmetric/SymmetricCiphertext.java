package ch.post.it.evoting.cryptoprimitives.symmetric;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;

/**
 * A symmetric ciphertext composed of a ciphertext and nonce.
 *
 * <p>Instances of this class are immutable.</p>
 */
public class SymmetricCiphertext {
	private final byte[] ciphertext;
	private final byte[] nonce;

	SymmetricCiphertext(final byte[] ciphertext, final byte[] nonce) {
		checkNotNull(ciphertext);
		checkNotNull(nonce);
		this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
		this.nonce = Arrays.copyOf(nonce, nonce.length);
	}

	public byte[] getCiphertext() {
		return Arrays.copyOf(ciphertext, ciphertext.length);
	}

	public byte[] getNonce() {
		return Arrays.copyOf(nonce, nonce.length);
	}
}
