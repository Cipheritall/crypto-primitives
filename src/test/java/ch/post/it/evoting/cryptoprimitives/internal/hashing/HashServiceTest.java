/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package ch.post.it.evoting.cryptoprimitives.internal.hashing;

import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.integerToByteArray;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.stringToByteArray;
import static com.google.common.primitives.Bytes.concat;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableByteArray;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

class HashServiceTest {

	private static final short TEST_INPUT_LENGTH = 5;

	private static SecureRandom secureRandom;
	private static HashService hashService;
	private static MessageDigest messageDigest;
	private static int hashLength;
	private static RandomService randomService;

	@BeforeAll
	static void setup() throws NoSuchAlgorithmException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		messageDigest = MessageDigest.getInstance("SHA3-256", BouncyCastleProvider.PROVIDER_NAME);
		hashLength = 32;
		hashService = HashService.getInstance();
		secureRandom = new SecureRandom();
		randomService = new RandomService();
	}

	static Stream<Arguments> jsonFileRecursiveHashArgumentProvider() {

		final List<TestParameters> parametersList = TestParameters.fromResource("/recursive-hash-sha3-256.json");

		return parametersList.stream().parallel().map(testParameters -> {

			final String messageDigest = testParameters.getContext().getJsonData("hash_function").getJsonNode().asText();

			final JsonData input = testParameters.getInput().getJsonData("values");

			final Hashable[] values = readInput(input).toArray(new Hashable[] {});

			final JsonData output = testParameters.getOutput();
			final byte[] hash = output.get("hash", byte[].class);

			return Arguments.of(messageDigest, values, hash, testParameters.getDescription());
		});
	}

	private static List<Hashable> readInput(final JsonData data) {
		final List<Hashable> values = new ArrayList<>();
		if (data.getJsonNode().isArray()) {
			final ArrayNode nodes = (ArrayNode) data.getJsonNode();
			for (final JsonNode node : nodes) {
				final JsonData nodeData = new JsonData(node);
				if (nodeData.getJsonNode().isArray()) {
					values.add(HashableList.from(readInput(nodeData)));
				} else {
					values.add(readValue(nodeData));
				}
			}
		} else {
			values.add(readValue(data));
		}

		return List.copyOf(values);
	}

	private static Hashable readValue(final JsonData data) {
		final String type = data.getJsonData("type").getJsonNode().asText();
		return switch (type) {
			case "string" -> HashableString.from(data.get("value", String.class));
			case "integer" -> HashableBigInteger.from(data.get("value", BigInteger.class));
			case "bytes" -> HashableByteArray.from(data.get("value", byte[].class));
			default -> throw new IllegalArgumentException(String.format("Unknown type: %s", type));
		};
	}

	@ParameterizedTest
	@MethodSource("jsonFileRecursiveHashArgumentProvider")
	@DisplayName("recursiveHash of specific input returns expected output")
	void testRecursiveHashWithRealValues(final String messageDigest, final Hashable[] input, final byte[] output, final String description) {
		if (!messageDigest.equals("SHA3-256")) {
			throw new IllegalArgumentException("Only SHA3-256 is currently supported as underlying hash");
		}
		final HashService testHashService = HashService.getInstance();
		final byte[] actual = testHashService.recursiveHash(input);
		assertArrayEquals(output, actual, String.format("assertion failed for: %s", description));
	}

	@Test
	void testRecursiveHashOfByteArrayReturnsHashOfByteArray() {
		final byte[] bytes = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes);
		final byte[] recursiveHash = hashService.recursiveHash(HashableByteArray.from(bytes));
		final byte[] regularHash = messageDigest.digest(concat(new byte[] { 0x00 }, bytes));
		assertArrayEquals(regularHash, recursiveHash);
	}

	@Test
	void testRecursiveHashOfStringReturnsHashOfString() {
		final String string = randomService.genRandomBase32String(TEST_INPUT_LENGTH);
		final byte[] expected = messageDigest.digest(concat(new byte[] { 0x02 }, stringToByteArray(string)));
		final byte[] recursiveHash = hashService.recursiveHash(HashableString.from(string));
		assertArrayEquals(expected, recursiveHash);
	}

	@Test
	void testRecursiveHashOfBigIntegerValue10ReturnsSameHashOfInteger10() {
		final BigInteger bigInteger = new BigInteger(2048, secureRandom);
		final byte[] recursiveHash = hashService.recursiveHash(HashableBigInteger.from(bigInteger));
		final byte[] regularHash = messageDigest.digest(concat(new byte[] { 0x01 }, integerToByteArray(bigInteger)));
		assertArrayEquals(regularHash, recursiveHash);
	}

	@Test
	void testRecursiveHashOfNullThrows() {
		final IllegalArgumentException illegalArgumentException =
				assertThrows(IllegalArgumentException.class, () -> hashService.recursiveHash((Hashable) null));

		assertEquals("Values contain a null value which cannot be hashed.", illegalArgumentException.getMessage());
	}

	@Test
	void testRecursiveHashOfTwoByteArraysReturnsHashOfConcatenatedIndividualHashes() {
		final byte[] bytes1 = new byte[TEST_INPUT_LENGTH];
		final byte[] bytes2 = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes1);
		secureRandom.nextBytes(bytes2);
		final HashableByteArray hashableBytes1 = HashableByteArray.from(bytes1);
		final HashableByteArray hashableBytes2 = HashableByteArray.from(bytes2);

		final HashableList list = HashableList.of(hashableBytes1, hashableBytes2);

		final byte[] hash = hashService.recursiveHash(list);

		final byte[] concatenation = new byte[hashLength * 2 + 1];
		concatenation[0] = 0x03;
		System.arraycopy(messageDigest.digest(concat(new byte[] { 0x00 }, bytes1)), 0, concatenation, 1, hashLength);
		System.arraycopy(messageDigest.digest(concat(new byte[] { 0x00 }, bytes2)), 0, concatenation, hashLength+1, hashLength);
		final byte[] expected = messageDigest.digest(concatenation);

		assertArrayEquals(expected, hash);
	}

	@Test
	void testRecursiveHashOfAByteArrayAndAListOfTwoByteArraysReturnsExpectedHash() {
		final byte[] bytes1 = new byte[TEST_INPUT_LENGTH];
		final byte[] bytes2 = new byte[TEST_INPUT_LENGTH];
		final byte[] bytes3 = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes1);
		secureRandom.nextBytes(bytes2);
		secureRandom.nextBytes(bytes3);
		final HashableByteArray hashableBytes1 = HashableByteArray.from(bytes1);
		final HashableByteArray hashableBytes2 = HashableByteArray.from(bytes2);
		final HashableByteArray hashableBytes3 = HashableByteArray.from(bytes3);
		final HashableList list = HashableList.of(hashableBytes2, hashableBytes3);
		final HashableList input = HashableList.of(hashableBytes1, list);

		final byte[] hash = hashService.recursiveHash(input);

		final byte[] subConcatenation = new byte[hashLength * 2 + 1];
		subConcatenation[0] = 0x03;
		System.arraycopy(messageDigest.digest(concat(new byte[] { 0x00 }, bytes2)), 0, subConcatenation, 1, hashLength);
		System.arraycopy(messageDigest.digest(concat(new byte[] { 0x00 }, bytes3)), 0, subConcatenation, hashLength+1, hashLength);
		final byte[] subHash = messageDigest.digest(subConcatenation);
		final byte[] concatenation = new byte[hashLength * 2+1];
		concatenation[0] = 0x03;
		System.arraycopy(messageDigest.digest(concat(new byte[] { 0x00 }, bytes1)), 0, concatenation, 1, hashLength);
		System.arraycopy(subHash, 0, concatenation, hashLength+1, hashLength);
		final byte[] expected = messageDigest.digest(concatenation);

		assertArrayEquals(expected, hash);
	}

	@Test
	void testRecursiveHashOfEmptyListThrows() {
		final HashableList list = List::of;
		assertThrows(IllegalArgumentException.class, () -> hashService.recursiveHash(list));
	}

	@Test
	void testRecursiveHashOfNestedEmptyListThrows() {
		final HashableList emptyList = List::of;
		final HashableList list = HashableList.of(HashableBigInteger.from(BigInteger.ONE), emptyList);
		assertThrows(IllegalArgumentException.class, () -> hashService.recursiveHash(list));
	}

	@Test
	void testRecursiveHashWithVarargsGivesSameResultAsWithList() {
		final HashableBigInteger first = genRandomHashableBigInteger();
		final HashableString second = genRandomHashableString();
		final HashableByteArray third = genRandomHashableByteArray();
		final HashableList list = HashableList.of(third);
		final HashableList input = HashableList.of(list, first, second);
		final byte[] varargsHash = hashService.recursiveHash(list, first, second);
		final byte[] listHash = hashService.recursiveHash(input);
		assertArrayEquals(listHash, varargsHash);
	}

	@Test
	void testRecursiveHashWithNestedListAndSpecificValues() throws IOException {
		final HashableBigInteger first = genRandomHashableBigInteger();
		final HashableByteArray second = genRandomHashableByteArray();
		final HashableString third = genRandomHashableString();
		final List<Hashable> subSubList = new LinkedList<>();
		subSubList.add(first);
		subSubList.add(second);
		final HashableList hashableSubSubList = HashableList.from(List.copyOf(subSubList));
		final HashableList subList = HashableList.of(third, hashableSubSubList);
		final HashableList input = HashableList.of(first, second, subList);

		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(0x03);
		outputStream.write(messageDigest.digest(concat(new byte[] { 0x01 }, integerToByteArray(first.toHashableForm()))));
		outputStream.write(messageDigest.digest(concat(new byte[] { 0x00 }, second.toHashableForm())));
		final byte[] expectedSubSubListHash = messageDigest.digest(outputStream.toByteArray());
		outputStream.close();

		final ByteArrayOutputStream outputStream1 = new ByteArrayOutputStream();
		outputStream1.write(0x03);
		outputStream1.write(messageDigest.digest(concat(new byte[] { 0x02 }, stringToByteArray(third.toHashableForm()))));
		outputStream1.write(expectedSubSubListHash);
		final byte[] expectedSubListHash = messageDigest.digest(outputStream1.toByteArray());
		outputStream1.close();

		final ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
		outputStream2.write(0x03);
		outputStream2.write(messageDigest.digest(concat(new byte[] { 0x01 }, integerToByteArray(first.toHashableForm()))));
		outputStream2.write(messageDigest.digest(concat(new byte[] { 0x00 }, second.toHashableForm())));
		outputStream2.write(expectedSubListHash);
		final byte[] expectedHash = messageDigest.digest(outputStream2.toByteArray());
		outputStream2.close();

		final byte[] hash = hashService.recursiveHash(input);

		assertArrayEquals(expectedHash, hash);
	}

	private HashableByteArray genRandomHashableByteArray() {
		final int size = secureRandom.nextInt(500);
		final byte[] bytes = new byte[size];
		secureRandom.nextBytes(bytes);
		return HashableByteArray.from(bytes);
	}

	private HashableString genRandomHashableString() {
		return HashableString.from(randomService.genRandomBase32String(TEST_INPUT_LENGTH));
	}

	private HashableBigInteger genRandomHashableBigInteger() {
		return HashableBigInteger.from(new BigInteger(50, secureRandom));
	}

	@RepeatedTest(10)
	void testThatTwoInputsThatAreIdenticalWhenConcatenatedButDifferentWhenSplitDoNotCollide() {
		final int size = secureRandom.nextInt(50) + 2;
		final byte[] concatenated = new byte[size];
		secureRandom.nextBytes(concatenated);

		final Split first = split(concatenated);
		Split second;
		do {
			second = split(concatenated);
		} while (Arrays.equals(second.start.toHashableForm(), first.start.toHashableForm()));

		final byte[] firstHash = hashService.recursiveHash(first.start, first.end);
		final byte[] secondHash = hashService.recursiveHash(second.start, second.end);

		assertNotEquals(firstHash, secondHash);
	}

	private Split split(final byte[] input) {
		final int split = secureRandom.nextInt(input.length);
		final byte[] first = new byte[split];
		final byte[] second = new byte[input.length - split];
		System.arraycopy(input, 0, first, 0, split);
		System.arraycopy(input, split, second, 0, input.length - split);
		return new Split(HashableByteArray.from(first), HashableByteArray.from(second));
	}

	@Test
	void testThatSimilarCharactersHashToDifferentValues() {
		final HashableString first = HashableString.from("e");
		final byte[] firstHash = hashService.recursiveHash(first);
		final HashableString second = HashableString.from("é");
		final byte[] secondHash = hashService.recursiveHash(second);
		assertNotEquals(firstHash, secondHash);
	}

	@Test
	@DisplayName("calling hashAndSquare with a null argument throws an exception.")
	void nullCheckTest() {

		final HashService hashService = HashService.getInstance();
		final BigInteger q = BigInteger.valueOf(11);
		final BigInteger p = BigInteger.valueOf(23);
		final BigInteger g = BigInteger.valueOf(2);

		final GqGroup group = new GqGroup(p, q, g);

		assertThrows(NullPointerException.class, () -> hashService.hashAndSquare(null, group));
		assertThrows(NullPointerException.class, () -> hashService.hashAndSquare(g, null));
	}

	@Test
	@DisplayName("calling hashAndSquare on a valid element with a hash service with a too big hash length throws an exception.")
	void hashAndSquareWithIncompatibleHashService() {
		final HashService hashService = HashService.getInstance();
		final BigInteger q = BigInteger.valueOf(11);
		final BigInteger p = BigInteger.valueOf(23);
		final BigInteger g = BigInteger.valueOf(2);

		final GqGroup group = new GqGroup(p, q, g);

		assertThrows(IllegalArgumentException.class, () -> hashService.hashAndSquare(g, group));
	}

	private static Stream<Arguments> onValidGqElementReturnsExpectedResultTestSource() {
		final GqGroup largeGqGroup = GroupTestData.getLargeGqGroup();
		final ZqGroup largeZqGroup = new ZqGroup(largeGqGroup.getQ().subtract(BigInteger.ONE));
		final BigInteger hugeBigInteger = new BigInteger(
				"12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
						+ "90123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
						+ "12345678901234567890123456789012345678901234567889").mod(largeZqGroup.getQ());

		return Stream.of(
				Arguments.of(ZqElement.create(BigInteger.valueOf(2), largeZqGroup), BigInteger.valueOf(9)),
				Arguments.of(ZqElement.create(BigInteger.ZERO, largeZqGroup), BigInteger.ONE),
				Arguments.of(ZqElement.create(hugeBigInteger, largeZqGroup),
						new BigInteger(
								"1524157875323883675049535156256668194500838287337600975522511812231126352691000152415888766956267751867094662703"
										+ "8562550221003043773814983252552966212772443410028959019878067369875323883776284103056503581773537875324142"
										+ "5392470931290961772004267645087943911297546105808629782048750495351663801249845254991620837982015295046486"
										+ "8506294772171754305749287913428140039628135128791345625361987773784484098503276941962810547407529340061877"
										+ "7625383002591070412741960252522481346377076666750190519886267337309751562263087639079520012193273126047859"
										+ "425087639153757049236500533455762536198787501905199875019052100"))
		);
	}

	@ParameterizedTest
	@MethodSource("onValidGqElementReturnsExpectedResultTestSource")
	@DisplayName("calling hashAndSquare on a valid gqElement with an hash call returning a specific mocked value returns the expected result.")
	void onValidGqElementReturnsExpectedResultTest(final ZqElement mockedHash, final BigInteger expectedResult) {

		final HashService hashService = spy(HashService.getInstance());
		doReturn((mockedHash)).when(hashService).recursiveHashToZq(any(), any());

		final GqGroup largeGqGroup = GroupTestData.getLargeGqGroup();

		assertEquals(expectedResult, hashService.hashAndSquare(BigInteger.ONE, largeGqGroup).getValue());
	}

	static Stream<Arguments> jsonFileRecursiveHashToZqArgumentProvider() {

		final List<TestParameters> parametersList = TestParameters.fromResource("/recursive-hash-to-zq.json");

		return parametersList.stream().parallel().map(testParameters -> {

			final JsonData input = testParameters.getInput();
			final BigInteger q = input.get("q", BigInteger.class);
			final JsonData valuesData = input.getJsonData("values");
			final Hashable[] values = readInput(valuesData).toArray(new Hashable[] {});

			final JsonData output = testParameters.getOutput();
			final BigInteger resultValue = output.get("result", BigInteger.class);
			final ZqElement result = ZqElement.create(resultValue, new ZqGroup(q));

			return Arguments.of(testParameters.getDescription(), q, values, result);
		});
	}

	@ParameterizedTest
	@MethodSource("jsonFileRecursiveHashToZqArgumentProvider")
	@DisplayName("recursiveHashToZq of specific input returns expected output")
	void testRecursiveHashToZqWithRealValues(final String description, final BigInteger q, final Hashable[] input, final ZqElement output) {
		final HashService testHashService = HashService.getInstance();
		final ZqElement actual = testHashService.recursiveHashToZq(q, input);
		assertEquals(output, actual, String.format("assertion failed for: %s", description));
	}

	/**
	 * The test below ascertains that the underlying MessageDigest instance respects the following equality:
	 *
	 * <pre>
	 *   digest(a || b) == { update(a); update(b); digest() }
	 * </pre>
	 */
	@RepeatedTest(100)
	void testAssumptionOnUnderlyingDigest() {
		final byte[] a = new byte[secureRandom.nextInt(20) + 10];
		final byte[] b = new byte[secureRandom.nextInt(20) + 10];
		final byte[] c = new byte[secureRandom.nextInt(20) + 10];

		secureRandom.nextBytes(a);
		secureRandom.nextBytes(b);
		secureRandom.nextBytes(c);

		messageDigest.reset();
		messageDigest.update(a);
		messageDigest.update(b);
		messageDigest.update(c);
		final byte[] updateThenDigest = messageDigest.digest();

		final byte[] concat = new byte[a.length + b.length + c.length];
		System.arraycopy(a, 0, concat, 0, a.length);
		System.arraycopy(b, 0, concat, a.length, b.length);
		System.arraycopy(c, 0, concat, a.length + b.length, c.length);

		final byte[] digestConcat = messageDigest.digest(concat);

		assertArrayEquals(updateThenDigest, digestConcat, "the underlying hash is expected to respect this assumption");
	}

	//Utilities
	private static class Split {
		final HashableByteArray start;
		final HashableByteArray end;

		Split(final HashableByteArray start, final HashableByteArray end) {
			this.start = start;
			this.end = end;
		}
	}
}
