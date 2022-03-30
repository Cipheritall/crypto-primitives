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

import static ch.post.it.evoting.cryptoprimitives.test.tools.data.PayloadSigner.signPayload;
import static ch.post.it.evoting.cryptoprimitives.test.tools.data.PayloadSigner.verifyPayload;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevel;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevelConfig;

class GenKeysAndCertServiceTest {

	static SecurityLevel securityLevel = SecurityLevelConfig.getSystemSecurityLevel();

	DigitalSignatures keysAndCertService;
	TestGenKeyPair genKeypPair;
	GetCertificate getCertificate;
	AuthorityInformation authorityInformation;
	Date defaultValidFrom;
	Date defaultValidUntil;

	@BeforeEach
	void setUp() {
		genKeypPair = new TestGenKeyPair();
		getCertificate = new GetCertificate(new RandomService(), securityLevel);
		authorityInformation = createAuthorityCertification();
		keysAndCertService = new GenKeysAndCertService(genKeypPair, getCertificate, authorityInformation);
		defaultValidFrom = toOldJavaDate(LocalDate.of(2022, 10, 20));
		defaultValidUntil = toOldJavaDate(LocalDate.of(2022, 12, 20));
	}

	@Test
	void nullParametersIsProvided_npeIsThrown() {
		// given
		final RandomService randomService = new RandomService();

		// when / then
		assertThrows(NullPointerException.class, () -> new GenKeysAndCertService(null, authorityInformation));
		assertThrows(NullPointerException.class, () -> new GenKeysAndCertService(randomService, null));
		assertThrows(NullPointerException.class, () -> keysAndCertService.genKeysAndCert(defaultValidFrom, null));
		assertThrows(NullPointerException.class, () -> keysAndCertService.genKeysAndCert(null, defaultValidUntil));
	}

	@Test
	void invalidDateInInput_fail() {
		// given

		// when / then
		assertThrows(IllegalArgumentException.class, () -> keysAndCertService.genKeysAndCert(defaultValidUntil, defaultValidFrom));
	}

	@Test
	void createValidCertificate_validityCheckWorksAsExpected() {
		// given
		Date invalidFrom = toOldJavaDate(LocalDate.of(2022, 10, 19));
		Date invalidUntil = toOldJavaDate(LocalDate.of(2022, 12, 21));

		// when
		final X509Certificate certificate = keysAndCertService.genKeysAndCert(defaultValidFrom, defaultValidUntil).getCertificate();

		// then
		assertEquals(defaultValidFrom, certificate.getNotBefore());
		assertEquals(defaultValidUntil, certificate.getNotAfter());
		assertDoesNotThrow(() -> certificate.checkValidity(defaultValidFrom));
		assertDoesNotThrow(() -> certificate.checkValidity(defaultValidUntil));
		assertThrows(CertificateNotYetValidException.class, () -> certificate.checkValidity(invalidFrom));
		assertThrows(CertificateExpiredException.class, () -> certificate.checkValidity(invalidUntil));
	}

	@Test
	void createValidCertificate_informationDataIsCorrectlySet() {
		// given
		String expectedFormattedInfo = "ST=dummy-St,L=dummy-L,O=dummy-O,C=dummy-C,CN=dummy-Cn";

		// when
		final X509Certificate certificate = keysAndCertService.genKeysAndCert(defaultValidFrom, defaultValidUntil).getCertificate();

		// then
		assertEquals(expectedFormattedInfo, certificate.getSubjectX500Principal().getName());
		assertEquals(expectedFormattedInfo, certificate.getIssuerX500Principal().getName());
	}

	@Test
	void createValidCertificate_validateSelfSignedSignature() {
		// given
		PublicKey publicKey = genKeypPair.getDummyPublicKey();

		// when
		final X509Certificate certificate = keysAndCertService.genKeysAndCert(defaultValidFrom, defaultValidUntil).getCertificate();

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
		final X509Certificate certificate = keysAndCertService.genKeysAndCert(defaultValidFrom, defaultValidUntil).getCertificate();
		final boolean[] actualKeyUsage = certificate.getKeyUsage();
		final List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();

		// then
		assertArrayEquals(expectedKeyUsage, actualKeyUsage);
		assertNull(extendedKeyUsage);
	}

	@Test
	void signPayloadWithKey_certificatePublicKeyValidThePayload() throws Exception {
		// given
		final GenKeysAndCertOutput output = keysAndCertService.genKeysAndCert(defaultValidFrom, defaultValidUntil);
		final Certificate certificate = output.getCertificate();
		final PrivateKey privateKey = output.getPrivateKey();

		final byte[] payload = createRandomPayload();

		// when
		final byte[] actual = signPayload(privateKey, payload);

		// then
		assertTrue(verifyPayload(certificate.getPublicKey(), payload, actual));
	}

	private Date toOldJavaDate(LocalDate localDate) {
		return Date.from(localDate.atStartOfDay(ZoneId.of("Europe/Paris")).toInstant());
	}

	private AuthorityInformation createAuthorityCertification() {
		return AuthorityInformation.builder().setCountry("dummy-C").setCommonName("dummy-Cn").setOrganisation("dummy-O").setLocality("dummy-L")
				.setState("dummy-St").build();
	}

	private byte[] createRandomPayload() throws Exception {
		final byte[] payload = new byte[10];
		SecureRandom.getInstanceStrong().nextBytes(payload);
		return payload;
	}

	/**
	 * We have to mock the key pair generation because, on Jenkins, it is taking a really long and inconstant time to run. The hypothesis is that on
	 * the VM on which Jenkins run, the entropy is not enough and the generation is blocking until it meets the entropy criterion.
	 */
	private static class TestGenKeyPair extends GenKeyPair {

		TestGenKeyPair() {
			super(securityLevel);
		}

		@Override
		public KeyPair get() {
			return new KeyPair(getDummyPublicKey(), getDummyPrivateKey());
		}

		PrivateKey getDummyPrivateKey() {
			try {
				KeyFactory keyFactory = KeyFactory.getInstance("RSASSA-PSS");
				byte[] key = Base64.getDecoder()
						.decode("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");
				return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(key));

			} catch (Exception e) {
				throw new IllegalStateException("Should not happen", e);
			}
		}

		PublicKey getDummyPublicKey() {
			try {
				KeyFactory keyFactory = KeyFactory.getInstance("RSASSA-PSS");
				byte[] key = Base64.getDecoder()
						.decode("MIIBoDALBgkqhkiG9w0BAQoDggGPADCCAYoCggGBAJmg0K7xBhD35WrcMKPHQekwXZ0m4eSjC9qQOWXlA5Cv5rqZLCWX7hXBuMGe3boSlZpfTO+zze/Sc691U34HBC+Vw/xlqMkjzuIuIn40lrm1j7ReDYySEOeA28VEqeF/RoYETt25qJGRNQ33A1ydzm7G2HnGBbEtVzKGH+bV/It/+cAdS9iffhqiCN++fAreX3hf9g2ETi4wZtFtP/FbMwzYjgA4ewntd4JljanRwhT0Ktc4Gr0GZo3r45j7WHt43sn+RFkBYrhFMmqfgMaXdCTnJc8/wid/QoRBMoxrteSJchmagBp/sOSI/LkC2Nr9iKJ/bHvPwQFcJ+8P6I3YWNCiG8AZyyDXQKkQQDdWDLWOt6MTuM2xkBTdRal6q40NcyS3lAsrTTFF74sQIJlPdoRFiNNlVONDJDOAqoVUqiDIaxFnG/RWx6xSuSCMoqMFEkrA7gT/FmQ0zZwTaAbyowhCV6CyM+g4SvTKlX8PqH7ObIEue8+3S/yUVxSVaHGqsQIDAQAB");
				return keyFactory.generatePublic(new X509EncodedKeySpec(key));

			} catch (Exception e) {
				throw new IllegalStateException("Should not happen", e);
			}
		}
	}

}