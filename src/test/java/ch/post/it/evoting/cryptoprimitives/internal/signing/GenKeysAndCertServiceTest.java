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

import static ch.post.it.evoting.cryptoprimitives.test.tools.data.PayloadSigner.signPayload;
import static ch.post.it.evoting.cryptoprimitives.test.tools.data.PayloadSigner.verifyPayload;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SecurityLevelInternal;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.internal.securitylevel.TestSignatureSupportingAlgorithm;
import ch.post.it.evoting.cryptoprimitives.signing.AuthorityInformation;
import ch.post.it.evoting.cryptoprimitives.signing.KeysAndCert;

class GenKeysAndCertServiceTest {

	private static final SecurityLevelInternal securityLevel = SecurityLevelConfig.getSystemSecurityLevel();

	private static GenKeysAndCertService keysAndCertService;
	private static AuthorityInformation authorityInformation;
	private static LocalDate defaultValidFrom;
	private static LocalDate defaultValidUntil;
	private static TestSignatureSupportingAlgorithm signatureAlgorithm;

	@BeforeAll
	static void beforeAll() {
		signatureAlgorithm = new TestSignatureSupportingAlgorithm();
		authorityInformation = AuthorityInformation.builder().setCountry("dummy-C").setCommonName("dummy-Cn").setOrganisation("dummy-O")
				.setLocality("dummy-L").setState("dummy-St").build();

		keysAndCertService = new GenKeysAndCertService(authorityInformation, signatureAlgorithm);

		defaultValidFrom = LocalDate.of(2022, 10, 20);
		defaultValidUntil = LocalDate.of(2022, 12, 20);
	}

	@Test
	void nullParametersIsProvided_npeIsThrown() {
		// given
		final RandomService randomService = new RandomService();

		// when / then
		assertThrows(NullPointerException.class, () -> new GenKeysAndCertService(null, signatureAlgorithm));
		assertThrows(NullPointerException.class, () -> new GenKeysAndCertService(authorityInformation, null));
		assertThrows(NullPointerException.class, () -> keysAndCertService.genKeysAndCert(defaultValidFrom, null));
		assertThrows(NullPointerException.class, () -> keysAndCertService.genKeysAndCert(null, defaultValidUntil));
	}

	@Test
	void invalidDateInInput_fail() {
		// given

		// when / then
		assertThrows(IllegalArgumentException.class, () -> keysAndCertService.genKeysAndCert(defaultValidUntil, defaultValidFrom));
	}

	@ParameterizedTest(name = "{0}: valid from {1} to {2}")
	@MethodSource("validityDateGenerator")
	void createValidCertificate_validityCheckWorksAsExpected(final String title, final LocalDate validFrom, final LocalDate validUntil) {
		// given
		final LocalDate invalidFrom = validFrom.minusDays(1);
		final LocalDate invalidUntil = validUntil.plusDays(1);

		// when
		final X509Certificate certificate = keysAndCertService.genKeysAndCert(validFrom, validUntil).certificate();

		// then
		assertAll("Validity dates represent same time independently of object used to represent them.",
				() -> assertEquals(toOldJavaDate(validFrom), certificate.getNotBefore()),
				() -> assertEquals(toOldJavaDate(validUntil), certificate.getNotAfter()),
				() -> assertEquals(validFrom, toNewJavaDate(certificate.getNotBefore())),
				() -> assertEquals(validUntil, toNewJavaDate(certificate.getNotAfter())));

		assertAll("Valid edge dates throw no exception.", () -> assertDoesNotThrow(() -> certificate.checkValidity(toOldJavaDate(validFrom))),
				() -> assertDoesNotThrow(() -> certificate.checkValidity(toOldJavaDate(validUntil))));

		assertAll("Invalid edge dates throw exception.",
				() -> assertThrows(CertificateNotYetValidException.class, () -> certificate.checkValidity(toOldJavaDate(invalidFrom))),
				() -> assertThrows(CertificateExpiredException.class, () -> certificate.checkValidity(toOldJavaDate(invalidUntil))));
	}

	static Stream<Arguments> validityDateGenerator() {
		final LocalDate dayLightSavingTimeMarch = LocalDate.of(2021, 3, 28);
		final LocalDate dayLightSavingTimeOctober = LocalDate.of(2021, 10, 31);

		return Stream.of(Arguments.of("random date", defaultValidFrom, defaultValidUntil),
				Arguments.of("march daylight saving time (from)", dayLightSavingTimeMarch, dayLightSavingTimeMarch.plusMonths(1)),
				Arguments.of("march daylight saving time (until)", dayLightSavingTimeMarch.minusMonths(1), dayLightSavingTimeMarch),
				Arguments.of("october daylight saving time (from)", dayLightSavingTimeOctober, dayLightSavingTimeOctober.plusMonths(1)),
				Arguments.of("october daylight saving time (until)", dayLightSavingTimeOctober.minusMonths(1), dayLightSavingTimeOctober));
	}

	@Test
	void createValidCertificate_informationDataIsCorrectlySet() {
		// given
		final String expectedFormattedInfo = "ST=dummy-St,L=dummy-L,O=dummy-O,C=dummy-C,CN=dummy-Cn";

		// when
		final X509Certificate certificate = keysAndCertService.genKeysAndCert(defaultValidFrom, defaultValidUntil).certificate();

		// then
		assertEquals(expectedFormattedInfo, certificate.getSubjectX500Principal().getName());
		assertEquals(expectedFormattedInfo, certificate.getIssuerX500Principal().getName());
	}

	@Test
	void createValidCertificate_validateSelfSignedSignature() {
		// given
		final PublicKey publicKey = signatureAlgorithm.getDummyPublicKey();

		// when
		final X509Certificate certificate = keysAndCertService.genKeysAndCert(defaultValidFrom, defaultValidUntil).certificate();

		// then
		assertDoesNotThrow(() -> certificate.verify(publicKey));
	}

	@Test
	void createValidCertificate_validateKeyUsage() throws CertificateParsingException {
		// given

		// see all key usage in the doc of java.security.cert.X509Certificate.getKeyUsage
		// digitalSignature -> (0)
		// keyCertSign      -> (5)
		final boolean[] expectedKeyUsage = new boolean[] { true, false, false, false, false, true, false, false, false };

		// when
		final X509Certificate certificate = keysAndCertService.genKeysAndCert(defaultValidFrom, defaultValidUntil).certificate();
		final boolean[] actualKeyUsage = certificate.getKeyUsage();
		final List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();

		// then
		assertArrayEquals(expectedKeyUsage, actualKeyUsage);
		assertNull(extendedKeyUsage);
	}

	@Test
	void signPayloadWithKey_certificatePublicKeyValidThePayload() throws Exception {
		// given
		final KeysAndCert output = keysAndCertService.genKeysAndCert(defaultValidFrom, defaultValidUntil);
		final Certificate certificate = output.certificate();
		final PrivateKey privateKey = output.privateKey();

		final byte[] payload = createRandomPayload();

		// when
		final byte[] actual = signPayload(privateKey, payload);

		// then
		assertTrue(verifyPayload(certificate.getPublicKey(), payload, actual));
	}

	private static Date toOldJavaDate(final LocalDate localDate) {
		return Date.from(localDate.atStartOfDay(ZoneId.of("Europe/Zurich")).toInstant());
	}

	private static LocalDate toNewJavaDate(final Date date) {
		return date.toInstant().atZone(ZoneId.of("Europe/Zurich")).toLocalDate();
	}

	private static byte[] createRandomPayload() throws Exception {
		final byte[] payload = new byte[10];
		SecureRandom.getInstanceStrong().nextBytes(payload);
		return payload;
	}
}
