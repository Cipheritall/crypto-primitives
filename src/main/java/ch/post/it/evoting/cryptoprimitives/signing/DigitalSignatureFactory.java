/*
 * Copyright 2022 by Swiss Post, Information Technology
 */
package ch.post.it.evoting.cryptoprimitives.signing;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;

public class DigitalSignatureFactory implements DigitalSignatures {

	private static final DigitalSignatures INSTANCE = new DigitalSignatureFactory();
	private final HashService hashService;
	private final RandomService randomService;

	public static DigitalSignatures getInstance() {
		return INSTANCE;
	}

	/**
	 * Instantiates a digital signature factory.
	 */
	private DigitalSignatureFactory() {
		hashService = HashService.getInstance();
		randomService = new RandomService();
	}

	@Override
	public GenKeysAndCertService createGenKeysAndCertService(final AuthorityInformation authorityInformation) {
		return new GenKeysAndCertService(randomService, authorityInformation);
	}

	@Override
	public SignatureGenerationService createSignatureGenerationService(final PrivateKey privateKey, final X509Certificate certificate) {
		return new SignatureGenerationService(privateKey, certificate, hashService);
	}

	@Override
	public SignatureVerificationService createSignatureVerificationService(final KeyStore trustStore) {
		return new SignatureVerificationService(trustStore, hashService);
	}
}
