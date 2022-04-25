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
package ch.post.it.evoting.cryptoprimitives.signing;

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevelConfig;

/**
 * Verifies signatures.
 */
public class SignatureVerificationService {

	private final KeyStore trustStore;
	private final HashService hashService;

	SignatureVerificationService(final KeyStore trustStore, final HashService hashService) {
		this.trustStore = trustStore;
		this.hashService = hashService;
	}

	/**
	 * Verifies that a signature is valid and from the expected authority.
	 *
	 * @param authorityId           The identifier of the authority. Must be non-null.
	 * @param message               The message that was signed. Must be non-null.
	 * @param additionalContextData Additional context data. Must be non-null. May be empty.
	 * @param signature             The signature of the message. Must be non-null.
	 * @return true if the signature is valid and the message has a timestamp during which the certificate was valid, false otherwise.
	 * @throws NullPointerException if any argument is null or if the certificate for the authorityId is not found.
	 */
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
		final byte[] h = hashService.recursiveHash(HashableList.of(m, c));

		return verify(pubKey, h, s);
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

	private boolean verify(final PublicKey publicKey, final byte[] hash, final byte[] signatureBytes) {
		checkNotNull(publicKey);
		checkNotNull(hash);
		checkNotNull(signatureBytes);

		final JcaContentVerifierProviderBuilder jcaContentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
		final ContentVerifierProvider contentVerifierProvider;
		try {
			contentVerifierProvider = jcaContentVerifierProviderBuilder.build(publicKey);
		} catch (final OperatorCreationException e) {
			throw new IllegalStateException("Could not build content verifier provider with public key.", e);
		}
		final AlgorithmIdentifier algorithmIdentifier = SecurityLevelConfig.getSystemSecurityLevel().getSigningParameters().getAlgorithmIdentifier();
		final ContentVerifier contentVerifier;
		try {
			contentVerifier = contentVerifierProvider.get(algorithmIdentifier);
		} catch (final OperatorCreationException e) {
			throw new IllegalStateException("Could not get content verifier for algorithm identifier.", e);
		}
		final OutputStream outputStream = contentVerifier.getOutputStream();
		try {
			outputStream.write(hash);
			outputStream.close();
		} catch (final IOException e) {
			throw new UncheckedIOException("Could not write hash to output stream.", e);
		}
		return contentVerifier.verify(signatureBytes);
	}
}
