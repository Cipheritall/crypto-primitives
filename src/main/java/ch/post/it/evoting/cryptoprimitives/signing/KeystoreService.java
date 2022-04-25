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
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.Supplier;

import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;

/**
 * Signs payload and verifies payload signature based on a trust store.
 * <p>
 * The trust store must contain the PK to sign payload and all the certificates of trusted sources to validate payload (direct trust).
 *
 * @param <T> Type of supplier which provides a lookup key to the keystore.
 */
public class KeystoreService<T extends Supplier<String>> {

	private static final String EMPTY_KEY_ENTRY_PASSWORD = "";

	private final SignatureGenerationService signatureGenerationService;
	private final SignatureVerificationService signatureVerificationService;
	private final T signingAlias;

	/**
	 * @param keyStoreStream containing the private key of the current component and the all certificates of other components. Use JKS format.
	 * @param keystoreType   of the keystore provided.
	 * @param password       to unlock the keystore.
	 * @param signingAlias   providing the alias of the component using this service. Must be present in the keystore.
	 * @param hashService    service to generate the hash for signing and verification.
	 */
	public KeystoreService(final InputStream keyStoreStream, final String keystoreType, final char[] password, final T signingAlias,
			final HashService hashService) {
		checkNotNull(keyStoreStream);
		checkNotNull(keystoreType);
		checkNotNull(password);
		checkNotNull(signingAlias);
		checkNotNull(hashService);

		this.signingAlias = signingAlias;

		try {
			final KeyStore keyStore = KeyStore.getInstance(keystoreType);
			keyStore.load(keyStoreStream, password);
			final PrivateKey key = (PrivateKey) keyStore.getKey(signingAlias.get(), EMPTY_KEY_ENTRY_PASSWORD.toCharArray());
			final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(signingAlias.get());
			this.signatureGenerationService = new SignatureGenerationService(key, certificate, hashService);
			this.signatureVerificationService = new SignatureVerificationService(keyStore, hashService);

		} catch (final UnrecoverableKeyException | CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
			throw new IllegalStateException("Impossible to initialize the KeystoreService. See nested exception.", e);
		}
	}

	/**
	 * Generates a signature for the given message.
	 *
	 * @param message               to be signed. Must be non-null.
	 * @param additionalContextData to add to signature. Must be non-null. May be empty.
	 * @return the signature for the message as a byte array
	 * @throws SignatureException if the message is timestamped at a date the certificate is not valid for.
	 */
	public byte[] generateSignature(final Hashable message, final Hashable additionalContextData) throws SignatureException {
		return signatureGenerationService.genSignature(message, additionalContextData);
	}

	/**
	 * Verifies that a signature is valid and from the expected authority.
	 *
	 * @param signerAlias           of the component that sent the message. Must be present in the keystore. Must be non-null.
	 * @param message               that was signed. Must be non-null.
	 * @param additionalContextData to add to signature. Must be non-null. May be empty.
	 * @param signature             of the message. Must be non-null.
	 * @return true if the signature is valid and the message has a timestamp during which the certificate was valid, false otherwise.
	 * @throws NullPointerException if message is null or if the certificate for the authorityId is not found.
	 */
	public boolean verifySignature(final T signerAlias, final Hashable message, final Hashable additionalContextData, final byte[] signature)
			throws SignatureException {
		return signatureVerificationService.verifySignature(signerAlias.get(), message, additionalContextData, signature);
	}

	/**
	 * @return the alias of the key used to sign messages.
	 */
	public T getSigningAlias() {
		return signingAlias;
	}

}
