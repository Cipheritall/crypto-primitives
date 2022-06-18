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
package ch.post.it.evoting.cryptoprimitives.internal.elgamal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mockStatic;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;

import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.Random;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevel;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

@DisplayName("An EncryptionParameters object")
class EncryptionParametersTest {

	private static final String SEED = "Election_name";
	private static final int NAME_MAX_LENGTH = 10;

	private static EncryptionParameters encryptionParameters;

	private final Random random = new RandomService();
	private final SecureRandom secureRandom = new SecureRandom();

	@BeforeAll
	static void setUpAll() {
		try (final MockedStatic<SecurityLevelConfig> mockedSecurityLevel = mockStatic(SecurityLevelConfig.class)) {
			mockedSecurityLevel.when(SecurityLevelConfig::getSystemSecurityLevel).thenReturn(SecurityLevel.TESTING_ONLY);
			encryptionParameters = new EncryptionParameters();
		}
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
		final String randomSeed = random.genRandomBase64String(electionNameLength);

		assertDoesNotThrow(() -> encryptionParameters.getEncryptionParameters(randomSeed));
	}

	static Stream<Arguments> getEncryptionParametersProvider() {
		final List<TestParameters> parametersList = TestParameters.fromResource("/elgamal/get-encryption-parameters.json");

		return parametersList.stream().parallel().map(testParameters -> {
			// Inputs.
			final JsonData input = testParameters.getInput();
			final String seed = input.get("seed", String.class);

			// Outputs.
			final JsonData output = testParameters.getOutput();
			final BigInteger p = output.get("p", BigInteger.class);
			final BigInteger q = output.get("q", BigInteger.class);
			final BigInteger g = output.get("g", BigInteger.class);

			try (final MockedStatic<SecurityLevelConfig> mockedSecurityLevel = mockStatic(SecurityLevelConfig.class)) {
				mockedSecurityLevel.when(SecurityLevelConfig::getSystemSecurityLevel).thenReturn(testParameters.getSecurityLevel());

				final GqGroup expectedParameters = new GqGroup(p, q, g);

				return Arguments.of(seed, expectedParameters, testParameters.getDescription(), testParameters.getSecurityLevel());
			}
		});
	}

	@ParameterizedTest(name = "bitLength = {0} and seed = {1}")
	@MethodSource("getEncryptionParametersProvider")
	@DisplayName("calling getEncryptionParameters with fixed seed gives expected parameters")
	void getEncryptionParameters(final String seed, final GqGroup expectedParameters,
			final String description, final SecurityLevel securityLevel) {

		try (final MockedStatic<SecurityLevelConfig> mockedSecurityLevel = mockStatic(SecurityLevelConfig.class)) {
			mockedSecurityLevel.when(SecurityLevelConfig::getSystemSecurityLevel).thenReturn(securityLevel);

			final GqGroup encryptionParameters = new EncryptionParameters().getEncryptionParameters(seed);

			assertEquals(expectedParameters, encryptionParameters, String.format("assertion failed for: %s", description));
		}
	}

}