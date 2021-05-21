/*
 * Copyright 2021 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ch.post.it.evoting.cryptoprimitives.CryptoPrimitives;
import ch.post.it.evoting.cryptoprimitives.CryptoPrimitivesService;
import ch.post.it.evoting.cryptoprimitives.SecurityLevel;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

@DisplayName("An EncryptionParameters object")
class EncryptionParametersTest {

	private static final String SEED = "Election_name";
	private static final int NAME_MAX_LENGTH = 10;

	private static EncryptionParameters encryptionParameters;

	private final CryptoPrimitives cryptoPrimitivesService = CryptoPrimitivesService.get();
	private final SecureRandom secureRandom = new SecureRandom();

	@BeforeAll
	static void setUpAll() {
		encryptionParameters = new EncryptionParameters(SecurityLevel.TESTING_ONLY);
	}

	@Test
	@DisplayName("constructed with a null SecurityLevel throws NullPointerException")
	void constructNullParam() {
		assertThrows(NullPointerException.class, () -> new EncryptionParameters(null));
	}

	@Test
	@DisplayName("calling getEncryptionParameters with null seed throws NullPointerException")
	void getEncryptionParametersNullSeed() {
		assertThrows(NullPointerException.class, () -> encryptionParameters.getEncryptionParameters(null));
	}

	@Test
	@DisplayName("calling getEncryptionParameters with fixed seed gives expected parameters")
	void getEncryptionParametersFixedSeed() {
		final GqGroup expectedParameters = new GqGroup(BigInteger.valueOf(150741944098619L), BigInteger.valueOf(75370972049309L),
				BigInteger.valueOf(3));

		assertEquals(expectedParameters, encryptionParameters.getEncryptionParameters(SEED));
	}

	@RepeatedTest(100)
	@DisplayName("calling getEncryptionParameters with random seed does not throw")
	void getEncryptionParametersRandomSeed() {
		final int electionNameLength = secureRandom.nextInt(NAME_MAX_LENGTH) + 1;
		final String randomSeed = cryptoPrimitivesService.genRandomBase64String(electionNameLength);

		assertDoesNotThrow(() -> encryptionParameters.getEncryptionParameters(randomSeed));
	}

	@Test
	@DisplayName("calling getEncryptionParameters with fixed seed and 2048 bitlength gives expected parameters")
	void getEncryptionParameters2048() throws IOException {
		final URL url = EncryptionParametersTest.class.getResource("/elgamal/encryption-parameters-2048.json");
		final ObjectMapper mapper = new ObjectMapper();
		final JsonNode rootNode = mapper.readTree(url);

		final String seed = rootNode.get("seed").asText();
		final BigInteger p = new BigInteger(rootNode.get("p").asText().substring(2), 16);
		final BigInteger q = new BigInteger(rootNode.get("q").asText().substring(2), 16);
		final BigInteger g = new BigInteger(rootNode.get("g").asText().substring(2), 16);
		final GqGroup expectedParameters = new GqGroup(p, q, g);

		final GqGroup encryptionParameters = new EncryptionParameters(SecurityLevel.DEFAULT).getEncryptionParameters(seed);

		assertEquals(expectedParameters, encryptionParameters);
	}

}