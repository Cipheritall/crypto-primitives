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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.signing.AuthorityInformation;

@DisplayName("SignatureService calling")
class SignatureVerificationServiceTest {

	private static final Hashable message = HashableString.from("message");
	private static final byte[] signature = "signature".getBytes();
	private static final Hashable additionalContextData = HashableList.of(HashableString.from("context"), HashableBigInteger.from(BigInteger.ONE),
			HashableString.from("1234"));
	private static String authorityId;
	private static KeyStore trustStore;
	private static HashService hashService;
	private static SignatureGenerationService signatureGenerationService;
	private static SignatureVerificationService signatureVerificationService;

	@BeforeAll
	static void init() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		Security.addProvider(new BouncyCastleProvider());
		final KeyPair keyPair = SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm().genKeyPair();
		final LocalDate from = LocalDate.of(2000, 1, 1);
		final LocalDate until = LocalDate.of(2035, 1, 1);
		final X509Certificate certificate = getCertificate(from, until, keyPair);
		authorityId = "authorityId";
		trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
		final char[] trustStorePassword = "abcdefgh".toCharArray();
		trustStore.load(null, trustStorePassword);
		trustStore.setCertificateEntry(authorityId, certificate);
		hashService = HashService.getInstance();
		signatureGenerationService = new SignatureGenerationService(keyPair.getPrivate(), certificate, hashService,
				SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm());
		signatureVerificationService = new SignatureVerificationService(trustStore, hashService,
				SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm());
	}

	private static X509Certificate getCertificate(final LocalDate from, final LocalDate until, final KeyPair keyPair) {
		final AuthorityInformation authorityInformation = AuthorityInformation.builder()
				.setCommonName("")
				.setCountry("")
				.setLocality("")
				.setState("")
				.setOrganisation("")
				.build();
		CertificateInfo certificateInfo = new CertificateInfo(authorityInformation);
		certificateInfo.setValidFrom(from);
		certificateInfo.setValidUntil(until);
		certificateInfo.setUsage(new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature));
		return SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm().getCertificate(keyPair, certificateInfo);
	}

	private static Stream<Arguments> getNullArguments() {
		return Stream.of(Arguments.of(null, message, additionalContextData, signature),
				Arguments.of(authorityId, null, additionalContextData, signature), Arguments.of(authorityId, message, null, signature),
				Arguments.of(authorityId, message, additionalContextData, null));
	}

	@ParameterizedTest
	@MethodSource("getNullArguments")
	@DisplayName("null parameters throws a NullPointerException")
	void verifySignatureWithNullParametersThrows(final String authorityId, final Hashable message, final Hashable additionalContextData,
			final byte[] signature) {
		assertThrows(NullPointerException.class,
				() -> signatureVerificationService.verifySignature(authorityId, message, additionalContextData, signature));
	}

	@Test
	@DisplayName("too early timestamp throws a SignatureException")
	void verifySignatureWithTooEarlyTimestampThrows() throws KeyStoreException {
		final Hashable message = HashableString.from("tooEarlyMessage");
		final Hashable additionalContextData = HashableString.from("tooEarly");
		final KeyPair keyPair = SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm().genKeyPair();
		final LocalDate from = LocalDate.now().plus(1, ChronoUnit.DAYS);
		final LocalDate until = from.plus(365, ChronoUnit.DAYS);
		final X509Certificate certificate = getCertificate(from, until, keyPair);
		final SignatureVerificationService signatureVerificationServiceNotYetValid = new SignatureVerificationService(trustStore, hashService,
				SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm());
		final String authorityId = "oldAuthorityId";
		trustStore.setCertificateEntry(authorityId, certificate);

		final SignatureException exception = assertThrows(SignatureException.class,
				() -> signatureVerificationServiceNotYetValid.verifySignature(authorityId, message, additionalContextData, signature));
		assertTrue(exception.getMessage().startsWith("The timestamp is outside the signing certificate's validity"));
	}

	@Test
	@DisplayName("too late timestamp throws a SignatureException")
	void verifySignatureWithTooLateTimestampThrows() throws KeyStoreException {
		final Hashable message = HashableString.from("tooLateMessage");
		final Hashable additionalContextData = HashableString.from("tooLate");
		final KeyPair keyPair = SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm().genKeyPair();
		final LocalDate now = LocalDate.now();
		final LocalDate from = now.minus(365, ChronoUnit.DAYS);
		final LocalDate until = now.minus(1, ChronoUnit.DAYS);
		final X509Certificate certificate = getCertificate(from, until, keyPair);
		final SignatureVerificationService signatureVerificationServiceNotYetValid = new SignatureVerificationService(trustStore, hashService,
				SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm());
		final String authorityId = "newAuthorityId";
		trustStore.setCertificateEntry(authorityId, certificate);

		final SignatureException exception = assertThrows(SignatureException.class,
				() -> signatureVerificationServiceNotYetValid.verifySignature(authorityId, message, additionalContextData, signature));
		assertTrue(exception.getMessage().startsWith("The timestamp is outside the signing certificate's validity"));
	}

	@Test
	@DisplayName("correct signature returns true")
	void verifySignatureWithCorrectSignatureVerifiesCorrectly() throws SignatureException {
		final byte[] signature = signatureGenerationService.genSignature(message, additionalContextData);
		assertTrue(signatureVerificationService.verifySignature(authorityId, message, additionalContextData, signature));
	}

	@Test
	@DisplayName("with key store not initialized throws IllegalStateExeption")
	void verifySignatureWithUninitializedKeyStore() throws KeyStoreException, SignatureException {
		final KeyPair keyPair = SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm().genKeyPair();
		final LocalDate from = LocalDate.of(2000, 1, 1);
		final LocalDate until = LocalDate.of(2035, 1, 1);
		final X509Certificate certificate = getCertificate(from, until, keyPair);
		final KeyStore uninitializedTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
		final SignatureGenerationService signatureGenerationService = new SignatureGenerationService(keyPair.getPrivate(), certificate, hashService,
				SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm());
		final SignatureVerificationService signatureVerificationService = new SignatureVerificationService(uninitializedTrustStore, hashService,
				SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm());

		final HashableString message = HashableString.from("Good to go!");
		final byte[] signature = signatureGenerationService.genSignature(message, additionalContextData);
		final IllegalStateException exception = assertThrows(IllegalStateException.class,
				() -> signatureVerificationService.verifySignature(authorityId, message, additionalContextData, signature));
		assertEquals("The trust store has not been initialized correctly.", exception.getMessage());
	}
}