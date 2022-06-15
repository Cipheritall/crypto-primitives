
package ch.post.it.evoting.cryptoprimitives.signing;

import java.security.SignatureException;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;

public interface SignatureVerification {

	/**
	 * Verifies that a signature is valid and from the expected authority.
	 *
	 * @param authorityId           The identifier of the authority. Must be non-null.
	 * @param message               The message that was signed. Must be non-null.
	 * @param additionalContextData Additional context data. Must be non-null. May be empty.
	 * @param signature             The signature of the message. Must be non-null.
	 * @return true if the signature is valid and the message has a timestamp during which the certificate was valid, false otherwise.
	 * @throws NullPointerException if any argument is null or if the certificate for the authorityId is not found.
	 * @throws SignatureException   if the message is timestamped at a date the certificate is not valid for.
	 */
	boolean verifySignature(String authorityId, Hashable message, Hashable additionalContextData, byte[] signature)
			throws SignatureException;
}
