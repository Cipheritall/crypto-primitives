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

import java.security.KeyPair;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableByteArray;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.signing.AuthorityInformation;

@DisplayName("SignatureService calling")
class SignatureGenerationServiceTest {

	private static HashService hashService;
	private static SignatureGenerationService signatureGenerationService;
	private static Hashable emptyContextData;

	@BeforeAll
	static void init() {
		Security.addProvider(new BouncyCastleProvider());
		final KeyPair keyPair = SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm().genKeyPair();
		final LocalDate from = LocalDate.of(2000, 1, 1);
		final LocalDate until = LocalDate.of(2035, 1, 1);
		final X509Certificate certificate = getCertificate(from, until, keyPair);
		hashService = HashService.getInstance();
		signatureGenerationService = new SignatureGenerationService(keyPair.getPrivate(), certificate, hashService,
				SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm());
		emptyContextData = HashableString.from("");
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

	@Test
	@DisplayName("null parameters throws a NullPointerException")
	void genSignatureWithNullParametersThrowsNullPointerException() {
		assertThrows(NullPointerException.class, () -> signatureGenerationService.genSignature(null, emptyContextData));
		final HashableByteArray message = HashableByteArray.from(new byte[] { 0b0000001 });
		assertThrows(NullPointerException.class, () -> signatureGenerationService.genSignature(message, null));
	}

	@Test
	@DisplayName("too early timestamp throws a SignatureException")
	void genSignatureWithTooEarlyTimestamp() {
		final Hashable message = HashableString.from("tooEarlyMessage");
		final Hashable additionalContextData = HashableString.from("tooEarly");
		final KeyPair keyPair = SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm().genKeyPair();
		final LocalDate from = LocalDate.now().plus(1, ChronoUnit.DAYS);
		final LocalDate until = from.plus(365, ChronoUnit.DAYS);
		final X509Certificate certificate = getCertificate(from, until, keyPair);
		final SignatureGenerationService signatureGenerationServiceNotYetValid = new SignatureGenerationService(keyPair.getPrivate(), certificate,
				hashService, SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm());

		final SignatureException exception = assertThrows(SignatureException.class,
				() -> signatureGenerationServiceNotYetValid.genSignature(message, additionalContextData));
		assertTrue(exception.getMessage().startsWith("The current timestamp is outside the signing certificate's validity"));
	}

	@Test
	@DisplayName("too late timestamp throws a SignatureException")
	void genSignatureWithTooLateTimestamp() {
		final Hashable message = HashableString.from("tooEarlyMessage");
		final Hashable context = HashableString.from("tooEarly");
		final KeyPair keyPair = SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm().genKeyPair();
		final LocalDate now = LocalDate.now();
		final LocalDate from = now.minus(365, ChronoUnit.DAYS);
		final LocalDate until = now.minus(1, ChronoUnit.DAYS);
		final X509Certificate certificate = getCertificate(from, until, keyPair);
		final SignatureGenerationService signatureGenerationServiceNotValidAnymore = new SignatureGenerationService(keyPair.getPrivate(), certificate,
				hashService, SecurityLevelConfig.getSystemSecurityLevel().getSignatureAlgorithm());

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