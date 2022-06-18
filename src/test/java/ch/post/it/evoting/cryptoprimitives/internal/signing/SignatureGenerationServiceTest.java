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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableByteArray;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevelConfig;

@DisplayName("SignatureService calling")
class SignatureGenerationServiceTest {

	private static HashService hashService;
	private static SignatureGenerationService signatureGenerationService;
	private static Hashable emptyContextData;

	@BeforeAll
	static void init() throws CertificateException, IOException, OperatorCreationException {
		Security.addProvider(new BouncyCastleProvider());
		final KeyPair keyPair = genKeyPair();
		final Date from = Date.from(LocalDate.of(2000, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant());
		final Date until = Date.from(LocalDate.of(2035, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant());
		final X509Certificate certificate = getCertificate(from, until, keyPair);
		hashService = HashService.getInstance();
		signatureGenerationService = new SignatureGenerationService(keyPair.getPrivate(), certificate, hashService);
		emptyContextData = HashableString.from("");
	}

	private static KeyPair genKeyPair() {
		final KeyPairGenerator rsa = SecurityLevelConfig.getSystemSecurityLevel().getSigningParameters().getKeyPairGenerator();
		return rsa.genKeyPair();
	}

	private static X509Certificate getCertificate(final Date from, final Date until, final KeyPair keyPair) throws
			CertificateException, IOException, OperatorCreationException {
		final SecureRandom random = new SecureRandom();

		// fill in certificate fields
		final X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
				.addRDN(BCStyle.CN, "it.post.ch")
				.build();
		final byte[] id = new byte[20];
		random.nextBytes(id);
		final BigInteger serial = new BigInteger(160, random);
		final X509v3CertificateBuilder certificate = new JcaX509v3CertificateBuilder(
				subject,
				serial,
				from,
				until,
				subject,
				keyPair.getPublic());
		certificate.addExtension(Extension.subjectKeyIdentifier, false, id);
		certificate.addExtension(Extension.authorityKeyIdentifier, false, id);
		final BasicConstraints constraints = new BasicConstraints(true);
		certificate.addExtension(
				Extension.basicConstraints,
				true,
				constraints.getEncoded());
		final KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
		certificate.addExtension(Extension.keyUsage, false, usage.getEncoded());
		final ExtendedKeyUsage usageEx = new ExtendedKeyUsage(new KeyPurposeId[] {
				KeyPurposeId.id_kp_serverAuth,
				KeyPurposeId.id_kp_clientAuth
		});
		certificate.addExtension(
				Extension.extendedKeyUsage,
				false,
				usageEx.getEncoded());

		// build BouncyCastle certificate
		final ContentSigner signer = SecurityLevelConfig.getSystemSecurityLevel().getSigningParameters().getContentSigner()
				.build(keyPair.getPrivate());
		final X509CertificateHolder holder = certificate.build(signer);

		// convert to JRE certificate
		final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		converter.setProvider(new BouncyCastleProvider());
		return converter.getCertificate(holder);
	}

	@Test
	@DisplayName("null parameters throws a NullPointerException")
	void genSignatureWithNullParametersThrowsNullPointerException() {
		assertThrows(NullPointerException.class, () -> signatureGenerationService.genSignature(null, emptyContextData));
		final HashableByteArray message = HashableByteArray.from(new byte[] { 0b0000001 });
		assertThrows(NullPointerException.class, () -> signatureGenerationService.genSignature(message, null));
	}

	@Test
	@DisplayName("too early timestamp throws a SignatureException")
	void genSignatureWithTooEarlyTimestamp() throws CertificateException, IOException, OperatorCreationException {
		final Hashable message = HashableString.from("tooEarlyMessage");
		final Hashable additionalContextData = HashableString.from("tooEarly");
		final KeyPair keyPair = genKeyPair();
		final Date from = Date.from(Instant.now().plusSeconds(3600));
		final Date until = Date.from(from.toInstant().plusSeconds(315360000));
		final X509Certificate certificate = getCertificate(from, until, keyPair);
		final SignatureGenerationService signatureGenerationServiceNotYetValid = new SignatureGenerationService(keyPair.getPrivate(), certificate,
				hashService);

		final SignatureException exception = assertThrows(SignatureException.class,
				() -> signatureGenerationServiceNotYetValid.genSignature(message, additionalContextData));
		assertTrue(exception.getMessage().startsWith("The current timestamp is outside the signing certificate's validity"));
	}

	@Test
	@DisplayName("too late timestamp throws a SignatureException")
	void genSignatureWithTooLateTimestamp() throws CertificateException, IOException, OperatorCreationException {
		final Hashable message = HashableString.from("tooEarlyMessage");
		final Hashable context = HashableString.from("tooEarly");
		final KeyPair keyPair = genKeyPair();
		final Date until = Date.from(Instant.now().minusSeconds(3600));
		final Date from = Date.from(until.toInstant().minusSeconds(315360000));
		final X509Certificate certificate = getCertificate(from, until, keyPair);
		final SignatureGenerationService signatureGenerationServiceNotValidAnymore = new SignatureGenerationService(keyPair.getPrivate(), certificate,
				hashService);

		final SignatureException exception = assertThrows(SignatureException.class,
				() -> signatureGenerationServiceNotValidAnymore.genSignature(message, context));
		assertTrue(exception.getMessage().startsWith("The current timestamp is outside the signing certificate's validity"));
	}

	@Test
	@DisplayName("valid certificate signs message")
	void genSignatureWithValidCertificateSigns() {
		final Hashable message = HashableString.from("Good to go!");
		assertDoesNotThrow(() -> signatureGenerationService.genSignature(message, emptyContextData));
	}
}