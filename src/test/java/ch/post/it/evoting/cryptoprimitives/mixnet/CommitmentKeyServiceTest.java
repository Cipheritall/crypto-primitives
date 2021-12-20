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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import ch.post.it.evoting.cryptoprimitives.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

class CommitmentKeyServiceTest {

	private static GqGroupGenerator generator;
	private static CommitmentKeyService commitmentKeyService;
	private static GqGroup gqGroup;

	private GqElement h;
	private List<GqElement> gs;

	@BeforeAll
	static void setUpAll() throws NoSuchAlgorithmException {
		gqGroup = GroupTestData.getGqGroup();
		generator = new GqGroupGenerator(gqGroup);
		HashService hashService = HashService.getInstance();
		commitmentKeyService = new CommitmentKeyService(hashService);
	}

	@BeforeEach
	void setUp() {
		h = generator.genNonIdentityNonGeneratorMember();
		gs = Stream.generate(generator::genNonIdentityNonGeneratorMember).limit(10).collect(Collectors.toList());
	}

	@Test
	@DisplayName("contains the correct commitment key")
	void constructionTest() {
		CommitmentKey commitmentKey = new CommitmentKey(h, gs);

		assertEquals(h, commitmentKey.stream().limit(1).collect(Collectors.toList()).get(0));
		assertEquals(gs, commitmentKey.stream().skip(1).collect(Collectors.toList()));
	}

	@Test
	void constructionFromNullParameterTest() {
		assertThrows(NullPointerException.class, () -> new CommitmentKey(null, gs));
		assertThrows(NullPointerException.class, () -> new CommitmentKey(h, null));

		List<GqElement> gList = new ArrayList<>(gs);
		gList.add(null);
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, gList));
	}

	@Test
	void constructionWithEmptyListTest() {
		List<GqElement> emptyList = new LinkedList<>();
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, emptyList));
	}

	@Test
	void constructionWithElementsFromDifferentGroupsTest() {
		List<GqElement> elements = new LinkedList<>(gs);
		GqGroup differentGroup = GroupTestData.getDifferentGqGroup(h.getGroup());
		GqGroupGenerator differentGroupGenerator = new GqGroupGenerator(differentGroup);
		elements.add(differentGroupGenerator.genNonIdentityNonGeneratorMember());

		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, elements));
	}

	@Test
	void constructionWithHAndGFromDifferentGroupsTest() {
		GqGroup differentGroup = GroupTestData.getDifferentGqGroup(h.getGroup());
		GqGroupGenerator differentGroupGenerator = new GqGroupGenerator(differentGroup);
		List<GqElement> gList = Stream.generate(differentGroupGenerator::genNonIdentityNonGeneratorMember).limit(3).collect(Collectors.toList());
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, gList));
	}

	@Test
	void constructionWithIdentityTest() {
		GqElement identity = h.getGroup().getIdentity();
		List<GqElement> elementsWithIdentity = new LinkedList<>(gs);
		elementsWithIdentity.add(identity);

		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(identity, gs));
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, elementsWithIdentity));
	}

	@Test
	void constructionWithGeneratorTest() {
		GqElement generator = h.getGroup().getGenerator();
		List<GqElement> elementsWithIdentity = new LinkedList<>(gs);
		elementsWithIdentity.add(generator);

		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(generator, gs));
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, elementsWithIdentity));
	}

	@Test
	void getVerifiableCommitmentKey() {

		final int numberOfCommitmentElements = 15;
		final GqGroup gqGroup = GroupTestData.getGroupP59();
		final CommitmentKey verifiableCommitmentKey = commitmentKeyService.getVerifiableCommitmentKey(numberOfCommitmentElements, gqGroup);

		assertNotNull(verifiableCommitmentKey.getGroup());

		final GqElement h = GqElementFactory.fromValue(BigInteger.valueOf(36), gqGroup);

		final List<GqElement> gqElements = Arrays.asList(
				GqElementFactory.fromValue(BigInteger.valueOf(28), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(15), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(35), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(45), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(26), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(53), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(22), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(48), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(25), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(20), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(9), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(12), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(29), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(21), gqGroup),
				GqElementFactory.fromValue(BigInteger.valueOf(4), gqGroup));

		final CommitmentKey expectedCommitmentKey = new CommitmentKey(h, gqElements);

		assertEquals(expectedCommitmentKey, verifiableCommitmentKey);
	}

	static Stream<Arguments> getVerifiableCommitmentKeyArgumentProvider() {
		final List<TestParameters> parametersList = TestParameters.fromResource("/mixnet/get-verifiable-commitment-key.json");

		return parametersList.stream().parallel().map(testParameters -> {
			// Context.
			final JsonData context = testParameters.getContext();
			final BigInteger p = context.get("p", BigInteger.class);
			final BigInteger q = context.get("q", BigInteger.class);
			final BigInteger g = context.get("g", BigInteger.class);

			try (MockedStatic<SecurityLevelConfig> mockedSecurityLevel = Mockito.mockStatic(SecurityLevelConfig.class)) {
				mockedSecurityLevel.when(SecurityLevelConfig::getSystemSecurityLevel).thenReturn(testParameters.getSecurityLevel());
				final GqGroup gqGroup = new GqGroup(p, q, g);

				// Input.
				final JsonData input = testParameters.getInput();
				final int numberOfElements = input.get("k", Integer.class);

				// Output.
				final JsonData output = testParameters.getOutput();
				final GqElement h = GqElementFactory.fromValue(output.get("h", BigInteger.class), gqGroup);
				final List<GqElement> gVector = Arrays.stream(output.get("g", BigInteger[].class))
						.map(value -> GqElementFactory.fromValue(value, gqGroup))
						.collect(Collectors.toList());
				final CommitmentKey expectedCommitmentKey = new CommitmentKey(h, gVector);

				return Arguments.of(numberOfElements, gqGroup, expectedCommitmentKey, testParameters.getDescription());
			}
		});
	}

	@ParameterizedTest(name = "{3}")
	@MethodSource("getVerifiableCommitmentKeyArgumentProvider")
	@DisplayName("with real values")
	void getVerifiableCommitmentKeyRealValues(final int numberOfElements, final GqGroup gqGroup, final CommitmentKey expectedCommitmentKey,
			final String description) {

		final CommitmentKey verifiableCommitmentKey = commitmentKeyService.getVerifiableCommitmentKey(numberOfElements, gqGroup);

		assertEquals(expectedCommitmentKey, verifiableCommitmentKey, String.format("assertion failed for: %s", description));
	}

	@Test
	void testGetVerifiableCommitmentKeyThrowsOnTooSmallGroup() {
		GqGroup group = GroupTestData.getGqGroup();
		int size = group.getQ().subtract(BigInteger.valueOf(3)).add(BigInteger.ONE).intValueExact();
		assertThrows(IllegalArgumentException.class, () -> commitmentKeyService.getVerifiableCommitmentKey(size, group));
	}

	@Test
	void testGetVerifiableCommitmentKeyNullGpGroup() {
		assertThrows(NullPointerException.class, () -> commitmentKeyService.getVerifiableCommitmentKey(1, null));
	}

	@Test
	void testGetVerifiableCommitmentKeyIncorrectNumberOfCommitmentElements() {
		IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> commitmentKeyService.getVerifiableCommitmentKey(0, gqGroup));
		assertEquals("The desired number of commitment elements must be in the range (0, q - 3]", illegalArgumentException.getMessage());

		illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> commitmentKeyService.getVerifiableCommitmentKey(-1, gqGroup));

		assertEquals("The desired number of commitment elements must be in the range (0, q - 3]", illegalArgumentException.getMessage());
	}
}
