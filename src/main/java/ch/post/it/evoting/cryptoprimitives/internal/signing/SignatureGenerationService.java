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

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import ch.post.it.evoting.cryptoprimitives.hashing.Hash;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.signing.SignatureGeneration;

/**
 * Signs and verifies signatures.
 */
public class SignatureGenerationService implements SignatureGeneration {

	private final PrivateKey privKey;
	private final X509Certificate certificate;
	private final Hash hash;

	public SignatureGenerationService(final PrivateKey privateKey, final X509Certificate certificate, final Hash hash) {
		this.privKey = privateKey;
		this.certificate = certificate;
		this.hash = hash;
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
			return sign(privKey, h);
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

	private byte[] sign(final PrivateKey privateKey, final byte[] message) {
		final JcaContentSignerBuilder contentSignerBuilder = SecurityLevelConfig.getSystemSecurityLevel().getSigningParameters().getContentSigner();
		final ContentSigner contentSigner;
		try {
			contentSigner = contentSignerBuilder.build(privateKey);
		} catch (final OperatorCreationException e) {
			throw new IllegalStateException("Could not build content signer with private key.", e);
		}
		final OutputStream outputStream = contentSigner.getOutputStream();
		try {
			outputStream.write(message);
			outputStream.close();
		} catch (final IOException e) {
			throw new UncheckedIOException("Could not write message to output stream.", e);
		}
		return contentSigner.getSignature();
	}
}
