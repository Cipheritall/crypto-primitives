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

import static java.time.LocalDate.now;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.Supplier;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableByteArray;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevel;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.signing.AuthorityInformation;
import ch.post.it.evoting.cryptoprimitives.signing.KeysAndCert;

class SignatureKeystoreServiceTest {

	private static final SecurityLevel securityLevel = SecurityLevelConfig.getSystemSecurityLevel();
	private static final String EMPTY_KEY_ENTRY_PASSWORD = "";
	private static final Hashable EMPTY_CONTEXT_DATA = HashableString.from("");
	private static final String KEYSTORE_TYPE = "JKS";

	private static GenKeysAndCertService genKeysAndCertService;
	private static HashService hashService;
	private static RandomService randomService;

	@BeforeAll
	static void beforeAll() {
		genKeysAndCertService = new GenKeysAndCertService(new TestGenKeyPair(securityLevel), new GetCertificate(new RandomService(), securityLevel),
				AuthorityInformation.builder().setCountry("dummy-C").setCommonName("dummy-Cn").setOrganisation("dummy-O").setLocality("dummy-L")
						.setState("dummy-St").build());

		randomService = new RandomService();
		hashService = HashService.getInstance();
	}

	@DisplayName("given two linked trust store, signing data with one of them, the other can validate the signature")
	@Test
	void valid() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, SignatureException {
		// given
		final String alias1 = "alias1";
		final String alias2 = "alias2";

		final char[] password1 = "password_1".toCharArray();
		final char[] password2 = "password_2".toCharArray();

		final KeyStore store1 = generateNewKeyStore(alias1);
		final KeyStore store2 = generateNewKeyStore(alias2);

		store2.setCertificateEntry(alias1, store1.getCertificate(alias1));
		store1.setCertificateEntry(alias2, store2.getCertificate(alias2));

		final SignatureKeystoreService<Supplier<String>> service1 = new SignatureKeystoreService<>(keyStoreToStream(store1, password1), KEYSTORE_TYPE,
				password1, (keystore) -> true, () -> alias1, hashService);
		final SignatureKeystoreService<Supplier<String>> service2 = new SignatureKeystoreService<>(keyStoreToStream(store2, password2), KEYSTORE_TYPE,
				password2, (keystore) -> true, () -> alias2, hashService);

		final HashableByteArray message = HashableByteArray.from(randomService.randomBytes(1000));

		// when
		final byte[] signature = service1.generateSignature(message, EMPTY_CONTEXT_DATA);

		// then
		assertTrue(service2.verifySignature(() -> alias1, message, EMPTY_CONTEXT_DATA, signature));
	}

	@DisplayName("given two unlinked trust store, signing data with one of them, the other cannot validate the signature")
	@Test
	void invalid() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, SignatureException {
		// given
		final String alias1 = "alias1";
		final String alias2 = "alias2";

		final char[] password1 = "password_1".toCharArray();
		final char[] password2 = "password_2".toCharArray();

		final KeyStore store1 = generateNewKeyStore(alias1);
		final KeyStore store2 = generateNewKeyStore(alias2);

		final SignatureKeystoreService<Supplier<String>> service1 = new SignatureKeystoreService<>(keyStoreToStream(store1, password1), KEYSTORE_TYPE,
				password1, (keystore) -> true, () -> alias1, hashService);
		final SignatureKeystoreService<Supplier<String>> service2 = new SignatureKeystoreService<>(keyStoreToStream(store2, password2), KEYSTORE_TYPE,
				password2, (keystore) -> true, () -> alias2, hashService);

		final HashableByteArray message = HashableByteArray.from(randomService.randomBytes(1000));

		// when
		final byte[] signature = service1.generateSignature(message, EMPTY_CONTEXT_DATA);

		// then
		assertThrows(NullPointerException.class, () -> service2.verifySignature(() -> alias1, message, EMPTY_CONTEXT_DATA, signature),
				"Could not find certificate for authority. [authorityId: store_1].");
	}

	@Test
	void testAliasGetter() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
		// given
		final String alias = "test";
		final char[] password = "password".toCharArray();
		final KeyStore keyStore = generateNewKeyStore(alias);
		final SignatureKeystoreService<Supplier<String>> service = new SignatureKeystoreService<>(keyStoreToStream(keyStore, password), KEYSTORE_TYPE,
				password, (keystore) -> true, () -> alias, hashService);

		// when
		final String selfAlias = service.getSigningAlias().get();

		// then
		assertEquals(alias, selfAlias);
	}

	@Test
	void testKeystoreValidationPass() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
		// given
		final String alias = "test";
		final char[] password = "password".toCharArray();
		final KeyStore keyStore = generateNewKeyStore(alias);

		// when / then
		assertDoesNotThrow(
				() -> new SignatureKeystoreService<>(keyStoreToStream(keyStore, password), KEYSTORE_TYPE, password, (keystore) -> true, () -> alias,
						hashService));
	}

	@Test
	void testKeystoreValidationFail() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
		// given
		final String alias = "test";
		final char[] password = "password".toCharArray();
		final KeyStore keyStore = generateNewKeyStore(alias);

		// when / then
		try (final InputStream inputStream = keyStoreToStream(keyStore, password)) {
			assertThrows(IllegalArgumentException.class,
					() -> new SignatureKeystoreService<>(inputStream, KEYSTORE_TYPE, password, (keystore) -> false, () -> alias, hashService));
		}
	}

	private KeyStore generateNewKeyStore(final String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
		final KeysAndCert keysAndCert = genKeysAndCertService.genKeysAndCert(now(), now().plusDays(1));

		final KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, EMPTY_KEY_ENTRY_PASSWORD.toCharArray());
		final KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(keysAndCert.privateKey(),
				new X509Certificate[] { keysAndCert.certificate() });
		keyStore.setEntry(alias, privateKeyEntry, new KeyStore.PasswordProtection("".toCharArray()));

		return keyStore;
	}

	private InputStream keyStoreToStream(final KeyStore keyStore, final char[] password)
			throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {

		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		keyStore.store(outputStream, password);
		return new ByteArrayInputStream(outputStream.toByteArray());
	}
}
