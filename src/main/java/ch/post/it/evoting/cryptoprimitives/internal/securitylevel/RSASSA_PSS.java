/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package ch.post.it.evoting.cryptoprimitives.internal.securitylevel;

import static com.google.common.base.Preconditions.checkNotNull;
import static java.util.Date.from;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import com.google.common.annotations.VisibleForTesting;

import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.internal.signing.CertificateInfo;

/**
 * This class is thread safe
 */
@SuppressWarnings({ "java:S101" })
public class RSASSA_PSS implements SignatureSupportingAlgorithm {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static final RSASSA_PSS INSTANCE = new RSASSA_PSS();
	private static final RandomService RANDOM_SERVICE = new RandomService();
	private static final String SIGNATURE_ALGORITHM = "SHA256WITHRSAANDMGF1";
	private static final String KEY_GENERATION_ALGORITHM = "RSASSA-PSS";
	private static final int KEY_LENGTH = 3072;
	private static final int SERIAL_LENGTH = 256;

	public static RSASSA_PSS getInstance() {
		return INSTANCE;
	}

	@VisibleForTesting
	RSASSA_PSS() {
		//Intentionally left blank
	}

	@Override
	public KeyPair genKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_GENERATION_ALGORITHM);
			generator.initialize(KEY_LENGTH);
			return generator.genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(
					String.format("Requested cryptographic algorithm is not available in the environment. [Requested: %s]", KEY_GENERATION_ALGORITHM),
					e);
		}
	}

	@Override
	public X509Certificate getCertificate(KeyPair keyPair, CertificateInfo info) {
		try {
			final X509v3CertificateBuilder certificateBuilder = createCertificateBuilder(keyPair.getPublic(), info);

			final ContentSigner signer = getContentSigner().build(keyPair.getPrivate());
			final X509CertificateHolder holder = certificateBuilder.build(signer);

			final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

			return converter.getCertificate(holder);

		} catch (OperatorCreationException | CertificateException e) {
			throw new IllegalStateException("There is a problem generating the certificate.", e);
		}
	}

	private JcaContentSignerBuilder getContentSigner() {
		return new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);
	}

	private X509v3CertificateBuilder createCertificateBuilder(final PublicKey publicKey, final CertificateInfo info) {
		final BigInteger serial = new BigInteger(RANDOM_SERVICE.randomBytes(SERIAL_LENGTH));

		final X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
				.addRDN(BCStyle.CN, info.getAuthorityInformation().getCommonName())
				.addRDN(BCStyle.C, info.getAuthorityInformation().getCountry())
				.addRDN(BCStyle.O, info.getAuthorityInformation().getOrganisation())
				.addRDN(BCStyle.L, info.getAuthorityInformation().getLocality())
				.addRDN(BCStyle.ST, info.getAuthorityInformation().getState())
				.build();

		final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				subject,
				serial,
				from(info.getValidFrom().atStartOfDay(ZoneId.of("Europe/Zurich")).toInstant()),
				from(info.getValidUntil().atStartOfDay(ZoneId.of("Europe/Zurich")).toInstant()),
				subject,
				publicKey);

		try {
			builder.addExtension(Extension.keyUsage, true, info.getUsage());
		} catch (CertIOException e) {
			throw new IllegalStateException("Badly configured extension.", e);
		}

		return builder;
	}

	@Override
	public byte[] sign(final PrivateKey privateKey, final byte[] message) {
		final JcaContentSignerBuilder contentSignerBuilder = getContentSigner();
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

	@Override
	public boolean verify(final PublicKey publicKey, final byte[] hash, final byte[] signatureBytes) {
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

		final DefaultSignatureAlgorithmIdentifierFinder algorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
		final AlgorithmIdentifier algorithmIdentifier = algorithmIdentifierFinder.find(SIGNATURE_ALGORITHM);

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
