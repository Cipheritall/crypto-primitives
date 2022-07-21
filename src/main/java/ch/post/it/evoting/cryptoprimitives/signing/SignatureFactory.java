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

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.signing.GenKeysAndCertService;
import ch.post.it.evoting.cryptoprimitives.internal.signing.SignatureGenerationService;
import ch.post.it.evoting.cryptoprimitives.internal.signing.SignatureVerificationService;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SecurityLevelInternal;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SignatureSupportingAlgorithm;

public class SignatureFactory {

	private static final SecurityLevelInternal SECURITY_LEVEL = SecurityLevelConfig.getSystemSecurityLevel();
	private static final SignatureFactory INSTANCE = new SignatureFactory();
	private final HashService hashService;
	private final SignatureSupportingAlgorithm signatureSupportingAlgorithm;

	public static SignatureFactory getInstance() {
		return INSTANCE;
	}

	/**
	 * Instantiates a digital signature factory.
	 */
	private SignatureFactory() {
		hashService = HashService.getInstance();
		signatureSupportingAlgorithm = SECURITY_LEVEL.getSignatureAlgorithm();
	}

	/**
	 * @param authorityInformation used to generate the certificate. Must not be null.
	 * @return a new GenKeysAndCertService.
	 */
	public GenKeysAndCert createGenKeysAndCert(final AuthorityInformation authorityInformation) {
		return new GenKeysAndCertService(authorityInformation, signatureSupportingAlgorithm);
	}

	/**
	 * @param privateKey  used by the service to sign the payload.
	 * @param certificate related to the private key to ensure that signed content can be validated.
	 * @return a new SignatureGenerationService.
	 */
	public SignatureGeneration createSignatureGeneration(final PrivateKey privateKey, final X509Certificate certificate) {
		return new SignatureGenerationService(privateKey, certificate, hashService, signatureSupportingAlgorithm);
	}

	/**
	 * @param trustStore which stores the certificates to validate messages.
	 * @return a new SignatureVerificationService.
	 */
	public SignatureVerification createSignatureVerification(final KeyStore trustStore) {
		return new SignatureVerificationService(trustStore, hashService, signatureSupportingAlgorithm);
	}
}
