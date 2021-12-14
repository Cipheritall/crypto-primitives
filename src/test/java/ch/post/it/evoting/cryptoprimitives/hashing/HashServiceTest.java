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
package ch.post.it.evoting.cryptoprimitives.hashing;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.integerToByteArray;
import static ch.post.it.evoting.cryptoprimitives.ConversionService.stringToByteArray;
import static com.google.common.primitives.Bytes.concat;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
import java.util.stream.Collectors;
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
import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
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

	@Test
	void testEmpty_SHA3_256_Constructor() {
		final HashService hashService = assertDoesNotThrow(HashService::new);

		assertEquals(32, hashService.getHashLength());
	}

	static Stream<Arguments> jsonFileArgumentProvider() {

		final List<TestParameters> parametersList = TestParameters.fromResource("/recursive-hash-sha3-256.json");

		return parametersList.stream().parallel().map(testParameters -> {

			final String messageDigest = testParameters.getContext().getJsonData("hash_function").getJsonNode().asText();

			final JsonData input = testParameters.getInput().getJsonData("values");

			Hashable[] values = readInput(input).toArray(new Hashable[] {});

			JsonData output = testParameters.getOutput();
			byte[] hash = output.get("hash", byte[].class);

			return Arguments.of(messageDigest, values, hash, testParameters.getDescription());
		});
	}

	private static ImmutableList<Hashable> readInput(JsonData data) {
		List<Hashable> values = new ArrayList<>();
		if (data.getJsonNode().isArray()) {
			ArrayNode nodes = (ArrayNode) data.getJsonNode();
			for (JsonNode node : nodes) {
				JsonData nodeData = new JsonData(node);
				if (nodeData.getJsonNode().isArray()) {
					values.add(HashableList.from(readInput(nodeData)));
				} else {
					values.add(readValue(nodeData));
				}
			}
		} else {
			values.add(readValue(data));
		}

		return ImmutableList.copyOf(values);
	}

	private static Hashable readValue(JsonData data) {
		String type = data.getJsonData("type").getJsonNode().asText();
		switch (type) {
		case "string":
			return HashableString.from(data.get("value", String.class));
		case "integer":
			return HashableBigInteger.from(data.get("value", BigInteger.class));
		case "bytes":
			return HashableByteArray.from(data.get("value", byte[].class));
		default:
			throw new IllegalArgumentException(String.format("Unknown type: %s", type));
		}
	}

	@ParameterizedTest
	@MethodSource("jsonFileArgumentProvider")
	@DisplayName("recursiveHash of specific input returns expected output")
	void testRecursiveHashWithRealValues(final String messageDigest, final Hashable[] input, final byte[] output, final String description) {
		if (!messageDigest.equals("SHA3-256")) {
			throw new IllegalArgumentException("Only SHA3-256 is currently supported as underlying hash");
		}
		HashService testHashService = HashService.getInstance();
		byte[] actual = testHashService.recursiveHash(input);
		assertArrayEquals(output, actual, String.format("assertion failed for: %s", description));
	}

	@Test
	void testRecursiveHashOfByteArrayReturnsHashOfByteArray() {
		byte[] bytes = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes);
		byte[] recursiveHash = hashService.recursiveHash(HashableByteArray.from(bytes));
		byte[] regularHash = messageDigest.digest(concat(new byte[] { 0x00 }, bytes));
		assertArrayEquals(regularHash, recursiveHash);
	}

	@Test
	void testRecursiveHashOfStringReturnsHashOfString() {
		String string = randomService.genRandomBase32String(TEST_INPUT_LENGTH);
		byte[] expected = messageDigest.digest(concat(new byte[] { 0x02 }, stringToByteArray(string)));
		byte[] recursiveHash = hashService.recursiveHash(HashableString.from(string));
		assertArrayEquals(expected, recursiveHash);
	}

	@Test
	void testRecursiveHashOfBigIntegerValue10ReturnsSameHashOfInteger10() {
		BigInteger bigInteger = new BigInteger(2048, secureRandom);
		byte[] recursiveHash = hashService.recursiveHash(HashableBigInteger.from(bigInteger));
		byte[] regularHash = messageDigest.digest(concat(new byte[] { 0x01 }, integerToByteArray(bigInteger)));
		assertArrayEquals(regularHash, recursiveHash);
	}

	@Test
	void testRecursiveHashOfNullThrows() {
		final IllegalArgumentException illegalArgumentException =
				assertThrows(IllegalArgumentException.class, () -> hashService.recursiveHash((Hashable) null));

		assertEquals("Values contain a null value which cannot be hashed.", illegalArgumentException.getMessage());
	}

	@Test
	void testRecursiveHashOfListOfOneElementReturnsHashOfElement() {
		byte[] bytes = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes);
		HashableByteArray byteArray = HashableByteArray.from(bytes);
		ImmutableList<Hashable> list = ImmutableList.of(byteArray);
		byte[] expected = hashService.recursiveHash(byteArray);
		byte[] hash = hashService.recursiveHash(HashableList.from(list));
		assertArrayEquals(expected, hash);
	}

	@Test
	void testRecursiveHashOfTwoByteArraysReturnsHashOfConcatenatedIndividualHashes() {
		byte[] bytes1 = new byte[TEST_INPUT_LENGTH];
		byte[] bytes2 = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes1);
		secureRandom.nextBytes(bytes2);
		HashableByteArray hashableBytes1 = HashableByteArray.from(bytes1);
		HashableByteArray hashableBytes2 = HashableByteArray.from(bytes2);

		HashableList list = HashableList.of(hashableBytes1, hashableBytes2);

		byte[] hash = hashService.recursiveHash(list);

		byte[] concatenation = new byte[hashLength * 2];
		System.arraycopy(messageDigest.digest(concat(new byte[] { 0x00 }, bytes1)), 0, concatenation, 0, hashLength);
		System.arraycopy(messageDigest.digest(concat(new byte[] { 0x00 }, bytes2)), 0, concatenation, hashLength, hashLength);
		byte[] expected = messageDigest.digest(concatenation);

		assertArrayEquals(expected, hash);
	}

	@Test
	void testRecursiveHashOfAByteArrayAndAListOfTwoByteArraysReturnsExpectedHash() {
		byte[] bytes1 = new byte[TEST_INPUT_LENGTH];
		byte[] bytes2 = new byte[TEST_INPUT_LENGTH];
		byte[] bytes3 = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes1);
		secureRandom.nextBytes(bytes2);
		secureRandom.nextBytes(bytes3);
		HashableByteArray hashableBytes1 = HashableByteArray.from(bytes1);
		HashableByteArray hashableBytes2 = HashableByteArray.from(bytes2);
		HashableByteArray hashableBytes3 = HashableByteArray.from(bytes3);
		HashableList list = HashableList.of(hashableBytes2, hashableBytes3);
		HashableList input = HashableList.of(hashableBytes1, list);

		byte[] hash = hashService.recursiveHash(input);

		byte[] subConcatenation = new byte[hashLength * 2];
		System.arraycopy(messageDigest.digest(concat(new byte[] { 0x00 }, bytes2)), 0, subConcatenation, 0, hashLength);
		System.arraycopy(messageDigest.digest(concat(new byte[] { 0x00 }, bytes3)), 0, subConcatenation, hashLength, hashLength);
		byte[] subHash = messageDigest.digest(subConcatenation);
		byte[] concatenation = new byte[hashLength * 2];
		System.arraycopy(messageDigest.digest(concat(new byte[] { 0x00 }, bytes1)), 0, concatenation, 0, hashLength);
		System.arraycopy(subHash, 0, concatenation, hashLength, hashLength);
		byte[] expected = messageDigest.digest(concatenation);

		assertArrayEquals(expected, hash);
	}

	@Test
	void testRecursiveHashOfEmptyListThrows() {
		HashableList list = ImmutableList::of;
		assertThrows(IllegalArgumentException.class, () -> hashService.recursiveHash(list));
	}

	@Test
	void testRecursiveHashOfNestedEmptyListThrows() {
		HashableList emptyList = ImmutableList::of;
		HashableList list = HashableList.of(HashableBigInteger.from(BigInteger.ONE), emptyList);
		assertThrows(IllegalArgumentException.class, () -> hashService.recursiveHash(list));
	}

	@Test
	void testRecursiveHashWithVarargsGivesSameResultAsWithList() {
		HashableBigInteger first = genRandomHashableBigInteger();
		HashableString second = genRandomHashableString();
		HashableByteArray third = genRandomHashableByteArray();
		HashableList list = HashableList.of(third);
		HashableList input = HashableList.of(list, first, second);
		byte[] varargsHash = hashService.recursiveHash(list, first, second);
		byte[] listHash = hashService.recursiveHash(input);
		assertArrayEquals(listHash, varargsHash);
	}

	@Test
	void testRecursiveHashWithNestedListAndSpecificValues() throws IOException {
		HashableBigInteger first = genRandomHashableBigInteger();
		HashableByteArray second = genRandomHashableByteArray();
		HashableString third = genRandomHashableString();
		List<Hashable> subSubList = new LinkedList<>();
		subSubList.add(first);
		subSubList.add(second);
		HashableList hashableSubSubList = HashableList.from(ImmutableList.copyOf(subSubList));
		HashableList subList = HashableList.of(third, hashableSubSubList);
		HashableList input = HashableList.of(first, second, subList);

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(messageDigest.digest(concat(new byte[] { 0x01 }, integerToByteArray(first.toHashableForm()))));
		outputStream.write(messageDigest.digest(concat(new byte[] { 0x00 }, second.toHashableForm())));
		byte[] expectedSubSubListHash = messageDigest.digest(outputStream.toByteArray());
		outputStream.close();

		ByteArrayOutputStream outputStream1 = new ByteArrayOutputStream();
		outputStream1.write(messageDigest.digest(concat(new byte[] { 0x02 }, stringToByteArray(third.toHashableForm()))));
		outputStream1.write(expectedSubSubListHash);
		byte[] expectedSubListHash = messageDigest.digest(outputStream1.toByteArray());
		outputStream1.close();

		ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
		outputStream2.write(messageDigest.digest(concat(new byte[] { 0x01 }, integerToByteArray(first.toHashableForm()))));
		outputStream2.write(messageDigest.digest(concat(new byte[] { 0x00 }, second.toHashableForm())));
		outputStream2.write(expectedSubListHash);
		byte[] expectedHash = messageDigest.digest(outputStream2.toByteArray());
		outputStream2.close();

		byte[] hash = hashService.recursiveHash(input);

		assertArrayEquals(expectedHash, hash);
	}

	private HashableByteArray genRandomHashableByteArray() {
		int size = secureRandom.nextInt(500);
		byte[] bytes = new byte[size];
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
		int size = secureRandom.nextInt(50) + 2;
		byte[] concatenated = new byte[size];
		secureRandom.nextBytes(concatenated);

		Split first = split(concatenated);
		Split second;
		do {
			second = split(concatenated);
		} while (Arrays.equals(second.start.toHashableForm(), first.start.toHashableForm()));

		byte[] firstHash = hashService.recursiveHash(first.start, first.end);
		byte[] secondHash = hashService.recursiveHash(second.start, second.end);

		assertNotEquals(firstHash, secondHash);
	}

	private Split split(byte[] input) {
		int split = secureRandom.nextInt(input.length);
		byte[] first = new byte[split];
		byte[] second = new byte[input.length - split];
		System.arraycopy(input, 0, first, 0, split);
		System.arraycopy(input, split, second, 0, input.length - split);
		return new Split(HashableByteArray.from(first), HashableByteArray.from(second));
	}

	@Test
	void testThatSimilarCharactersHashToDifferentValues() {
		HashableString first = HashableString.from("e");
		byte[] firstHash = hashService.recursiveHash(first);
		HashableString second = HashableString.from("é");
		byte[] secondHash = hashService.recursiveHash(second);
		assertNotEquals(firstHash, secondHash);
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
		byte[] a = new byte[secureRandom.nextInt(20) + 10];
		byte[] b = new byte[secureRandom.nextInt(20) + 10];
		byte[] c = new byte[secureRandom.nextInt(20) + 10];

		secureRandom.nextBytes(a);
		secureRandom.nextBytes(b);
		secureRandom.nextBytes(c);

		messageDigest.reset();
		messageDigest.update(a);
		messageDigest.update(b);
		messageDigest.update(c);
		final byte[] updateThenDigest = messageDigest.digest();

		byte[] concat = new byte[a.length + b.length + c.length];
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

		Split(HashableByteArray start, HashableByteArray end) {
			this.start = start;
			this.end = end;
		}
	}
}
