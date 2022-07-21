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

import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;

import ch.post.it.evoting.cryptoprimitives.hashing.Hash;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SignatureSupportingAlgorithm;
import ch.post.it.evoting.cryptoprimitives.signing.SignatureGeneration;

/**
 * Signs and verifies signatures.
 */
public class SignatureGenerationService implements SignatureGeneration {
	private final PrivateKey privKey;
	private final X509Certificate certificate;
	private final Hash hash;
	private final SignatureSupportingAlgorithm signatureSupportingAlgorithm;

	public SignatureGenerationService(final PrivateKey privateKey, final X509Certificate certificate, final Hash hash, 
			final SignatureSupportingAlgorithm signatureSupportingAlgorithm) {
		this.privKey = privateKey;
		this.certificate = certificate;
		this.hash = hash;
		this.signatureSupportingAlgorithm = signatureSupportingAlgorithm;
	}

	/**
	 * See {@link SignatureGeneration#genSignature}
	 */
	@Override
	public byte[] genSignature(final Hashable message, final Hashable additionalContextData) throws SignatureException {
		checkNotNull(message);
		checkNotNull(additionalContextData);

		final Hashable m = message;
		final Hashable c = additionalContextData;

		final Instant t = getTimeStamp();
		final Instant validFrom = certificate.getNotBefore().toInstant();
		final Instant validUntil = certificate.getNotAfter().toInstant();
		if (validFrom.compareTo(t) <= 0 && t.compareTo(validUntil) < 0) {
			final byte[] h = hash.recursiveHash(HashableList.of(m, c));
			return signatureSupportingAlgorithm.sign(privKey, h);
		} else {
			final String errorMessage = String.format(
					"The current timestamp is outside the signing certificate's validity [valid from: %s, valid until: %s, timestamp: %s].",
					validFrom, validUntil, t);
			throw new SignatureException(errorMessage);
		}
	}

	private Instant getTimeStamp() {
		return Instant.now();
	}
}
