/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ch.post.it.evoting.cryptoprimitives.internal.signing;

import static com.google.common.base.Preconditions.checkNotNull;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;

import ch.post.it.evoting.cryptoprimitives.hashing.Hash;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SignatureSupportingAlgorithm;
import ch.post.it.evoting.cryptoprimitives.signing.SignatureVerification;

/**
 * Verifies signatures.
 */
public class SignatureVerificationService implements SignatureVerification {

	private final KeyStore trustStore;
	private final Hash hash;
	private final SignatureSupportingAlgorithm signatureSupportingAlgorithm;

	public SignatureVerificationService(final KeyStore trustStore, final Hash hash, final SignatureSupportingAlgorithm signatureSupportingAlgorithm) {
		this.trustStore = trustStore;
		this.hash = hash;
		this.signatureSupportingAlgorithm = signatureSupportingAlgorithm;
	}

	/**
	 * See {@link SignatureVerification#verifySignature}
	 * @param authorityId           The identifier of the authority. Must be non-null.
	 * @param message               The message that was signed. Must be non-null.
	 * @param additionalContextData Additional context data. Must be non-null. May be empty.
	 * @param signature             The signature of the message. Must be non-null.
	 * @return
	 * @throws SignatureException
	 */
	@Override
	public boolean verifySignature(final String authorityId, final Hashable message, final Hashable additionalContextData, final byte[] signature)
			throws SignatureException {
		final String id = checkNotNull(authorityId);
		final Hashable m = checkNotNull(message);
		final Hashable c = checkNotNull(additionalContextData);
		final byte[] s = checkNotNull(signature);

		final X509Certificate cert = findCertificate(id);
		final Instant t = getTimeStamp();
		final Instant validFrom = cert.getNotBefore().toInstant();
		final Instant validUntil = cert.getNotAfter().toInstant();
		if (t.compareTo(validFrom) < 0 || t.compareTo(validUntil) >= 0) {
			final String errorMessage = String.format(
					"The timestamp is outside the signing certificate's validity [valid from: %s, valid until: %s, timestamp: %s].", validFrom,
					validUntil, t);
			throw new SignatureException(errorMessage);
		}

		final PublicKey pubKey = cert.getPublicKey();
		final byte[] h = hash.recursiveHash(HashableList.of(m, c));

		return signatureSupportingAlgorithm.verify(pubKey, h, s);
	}

	private Instant getTimeStamp() {
		return Instant.now();
	}

	private X509Certificate findCertificate(final String authorityId) {
		try {
			return checkNotNull((X509Certificate) trustStore.getCertificate(authorityId),
					String.format("Could not find certificate for authority. [authorityId: %s].", authorityId));
		} catch (final KeyStoreException e) {
			throw new IllegalStateException("The trust store has not been initialized correctly.");
		}
	}


}
