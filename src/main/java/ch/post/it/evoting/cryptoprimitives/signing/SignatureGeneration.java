package ch.post.it.evoting.cryptoprimitives.signing;

import java.security.SignatureException;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;

public interface SignatureGeneration {

	/**
	 * Generates a signature for the given message.
	 *
	 * @param message               m, the message to be signed. Must be non-null.
	 * @param additionalContextData c, additional context data. Must be non-null. May be empty.
	 * @return the signature for the message as a byte array
	 * @throws SignatureException if the message is timestamped at a date the certificate is not valid for.
	 */
	byte[] genSignature(Hashable message, Hashable additionalContextData) throws SignatureException;
}
