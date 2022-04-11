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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.stream.Stream;

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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableByteArray;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevelConfig;

@DisplayName("SignatureService calling")
class SignatureServiceTest {

	private static String authorityId;
	private static KeyStore trustStore;
	private static HashService hashService;
	private static SignatureService signatureService;

	@BeforeAll
	static void init() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException, KeyStoreException {
		Security.addProvider(new BouncyCastleProvider());
		final KeyPair keyPair = genKeyPair();
		final Date from = Date.from(LocalDate.of(2000, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant());
		final Date until = Date.from(LocalDate.of(2035, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant());
		final X509Certificate certificate = getCertificate(from, until, keyPair);
		authorityId = "authorityId";
		trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] trustStorePassword = "abcdefgh".toCharArray();
		trustStore.load(null, trustStorePassword);
		trustStore.setCertificateEntry(authorityId, certificate);
		hashService = HashService.getInstance();
		signatureService = new SignatureService(keyPair.getPrivate(), certificate, trustStore, hashService);
	}

	private static KeyPair genKeyPair() {
		final KeyPairGenerator rsa = SecurityLevelConfig.getSystemSecurityLevel().getSigningParameters().getKeyPairGenerator();
		return rsa.genKeyPair();
	}

	private static X509Certificate getCertificate(final Date from, final Date until, final KeyPair keyPair) throws
			CertificateException, IOException, OperatorCreationException {
		SecureRandom random = new SecureRandom();

		// fill in certificate fields
		X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
				.addRDN(BCStyle.CN, "it.post.ch")
				.build();
		byte[] id = new byte[20];
		random.nextBytes(id);
		BigInteger serial = new BigInteger(160, random);
		X509v3CertificateBuilder certificate = new JcaX509v3CertificateBuilder(
				subject,
				serial,
				from,
				until,
				subject,
				keyPair.getPublic());
		certificate.addExtension(Extension.subjectKeyIdentifier, false, id);
		certificate.addExtension(Extension.authorityKeyIdentifier, false, id);
		BasicConstraints constraints = new BasicConstraints(true);
		certificate.addExtension(
				Extension.basicConstraints,
				true,
				constraints.getEncoded());
		KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
		certificate.addExtension(Extension.keyUsage, false, usage.getEncoded());
		ExtendedKeyUsage usageEx = new ExtendedKeyUsage(new KeyPurposeId[] {
				KeyPurposeId.id_kp_serverAuth,
				KeyPurposeId.id_kp_clientAuth
		});
		certificate.addExtension(
				Extension.extendedKeyUsage,
				false,
				usageEx.getEncoded());

		// build BouncyCastle certificate
		ContentSigner signer = SecurityLevelConfig.getSystemSecurityLevel().getSigningParameters().getContentSigner()
				.build(keyPair.getPrivate());
		X509CertificateHolder holder = certificate.build(signer);

		// convert to JRE certificate
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		converter.setProvider(new BouncyCastleProvider());
		return converter.getCertificate(holder);
	}

	@Nested
	@DisplayName("genSignature with")
	class GenSignatureTest {

		@Test
		@DisplayName("null parameters throws a NullPointerException")
		void genSignatureWithNullParametersThrowsNullPointerException() {
			assertThrows(NullPointerException.class, () -> signatureService.genSignature(null, ""));
			final HashableByteArray message = HashableByteArray.from(new byte[] { 0b0000001 });
			assertThrows(NullPointerException.class, () -> signatureService.genSignature(message, null));
		}

		@Test
		@DisplayName("too early timestamp throws a SignatureException")
		void genSignatureWithTooEarlyTimestamp() throws CertificateException, IOException, OperatorCreationException {
			final Hashable message = HashableString.from("tooEarlyMessage");
			final String context = "tooEarly";
			final KeyPair keyPair = genKeyPair();
			final Date from = Date.from(Instant.now().plusSeconds(3600));
			final Date until = Date.from(from.toInstant().plusSeconds(315360000));
			final X509Certificate certificate = getCertificate(from, until, keyPair);
			final SignatureService signatureServiceNotYetValid = new SignatureService(keyPair.getPrivate(), certificate, trustStore, hashService);

			final SignatureException exception = assertThrows(SignatureException.class,
					() -> signatureServiceNotYetValid.genSignature(message, context));
			assertTrue(exception.getMessage().startsWith("The current timestamp is outside the signing certificate's validity"));
		}

		@Test
		@DisplayName("too late timestamp throws a SignatureException")
		void genSignatureWithTooLateTimestamp() throws CertificateException, IOException, OperatorCreationException {
			final Hashable message = HashableString.from("tooEarlyMessage");
			final String context = "tooEarly";
			final KeyPair keyPair = genKeyPair();
			final Date until = Date.from(Instant.now().minusSeconds(3600));
			final Date from = Date.from(until.toInstant().minusSeconds(315360000));
			final X509Certificate certificate = getCertificate(from, until, keyPair);
			final SignatureService signatureServiceNotValidAnymore = new SignatureService(keyPair.getPrivate(), certificate, trustStore, hashService);

			final SignatureException exception = assertThrows(SignatureException.class,
					() -> signatureServiceNotValidAnymore.genSignature(message, context));
			assertTrue(exception.getMessage().startsWith("The current timestamp is outside the signing certificate's validity"));
		}

		@Test
		@DisplayName("valid certificate signs message")
		void genSignatureWithValidCertificateSigns() {
			final Hashable message = HashableString.from("Good to go!");
			assertDoesNotThrow(() -> signatureService.genSignature(message, ""));
		}
	}

	@Nested
	@DisplayName("verifySignature with")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class VerifySignatureTest {
		final Hashable message = HashableString.from("message");
		final String contextData = "context";
		final byte[] signature = "signature".getBytes();

		private Stream<Arguments> getNullArguments() {
			return Stream.of(
					Arguments.of(null, message, contextData, signature),
					Arguments.of(authorityId, null, contextData, signature),
					Arguments.of(authorityId, message, null, signature),
					Arguments.of(authorityId, message, contextData, null)
			);
		}

		@ParameterizedTest
		@MethodSource("getNullArguments")
		@DisplayName("null parameters throws a NullPointerException")
		void verifySignatureWithNullParametersThrows(final String authorityId, final Hashable message, final String contextData,
				final byte[] signature) {
			assertThrows(NullPointerException.class, () -> signatureService.verifySignature(authorityId, message, contextData, signature));
		}

		@Test
		@DisplayName("too early timestamp throws a SignatureException")
		void verifySignatureWithTooEarlyTimestampThrows()
				throws KeyStoreException, CertificateException, IOException, OperatorCreationException {
			final Hashable message = HashableString.from("tooEarlyMessage");
			final String contextData = "tooEarly";
			final KeyPair keyPair = genKeyPair();
			final Date from = Date.from(Instant.now().plusSeconds(3600));
			final Date until = Date.from(from.toInstant().plusSeconds(315360000));
			final X509Certificate certificate = getCertificate(from, until, keyPair);
			final SignatureService signatureServiceNotYetValid = new SignatureService(keyPair.getPrivate(), certificate, trustStore, hashService);
			final String authorityId = "oldAuthorityId";
			trustStore.setCertificateEntry(authorityId, certificate);

			final SignatureException exception = assertThrows(SignatureException.class,
					() -> signatureServiceNotYetValid.verifySignature(authorityId, message, contextData, signature));
			assertTrue(exception.getMessage().startsWith("The timestamp is outside the signing certificate's validity"));
		}

		@Test
		@DisplayName("too late timestamp throws a SignatureException")
		void verifySignatureWithTooLateTimestampThrows()
				throws KeyStoreException, CertificateException, IOException, OperatorCreationException {
			final Hashable message = HashableString.from("tooLateMessage");
			final String contextData = "tooLate";
			final KeyPair keyPair = genKeyPair();
			final Date until = Date.from(Instant.now().minusSeconds(3600));
			final Date from = Date.from(until.toInstant().minusSeconds(315360000));
			final X509Certificate certificate = getCertificate(from, until, keyPair);
			final SignatureService signatureServiceNotYetValid = new SignatureService(keyPair.getPrivate(), certificate, trustStore, hashService);
			final String authorityId = "newAuthorityId";
			trustStore.setCertificateEntry(authorityId, certificate);

			final SignatureException exception = assertThrows(SignatureException.class,
					() -> signatureServiceNotYetValid.verifySignature(authorityId, message, contextData, signature));
			assertTrue(exception.getMessage().startsWith("The timestamp is outside the signing certificate's validity"));
		}

		@Test
		@DisplayName("correct signature returns true")
		void verifySignatureWithCorrectSignatureVerifiesCorrectly() throws SignatureException {
			final byte[] signature = signatureService.genSignature(message, contextData);
			assertTrue(signatureService.verifySignature(authorityId, message, contextData, signature));
		}

		@Test
		@DisplayName("with key store not initialized throws IllegalStateExeption")
		void verifySignatureWithUninitializedKeyStore()
				throws CertificateException, IOException, OperatorCreationException, KeyStoreException, SignatureException {
			final KeyPair keyPair = genKeyPair();
			final Date from = Date.from(LocalDate.of(2000, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant());
			final Date until = Date.from(LocalDate.of(2035, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant());
			final X509Certificate certificate = getCertificate(from, until, keyPair);
			final KeyStore uninitializedTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
			final SignatureService signatureService = new SignatureService(keyPair.getPrivate(), certificate, uninitializedTrustStore, hashService);

			final HashableString message = HashableString.from("Good to go!");
			final byte[] signature = signatureService.genSignature(message, contextData);
			final IllegalStateException exception = assertThrows(IllegalStateException.class,
					() -> signatureService.verifySignature(authorityId, message, contextData, signature));
			assertEquals(String.format("Could not find certificate for authority. [authorityId: %s].", authorityId), exception.getMessage());
		}
	}
}