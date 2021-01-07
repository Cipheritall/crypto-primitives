/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

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

import ch.post.it.evoting.cryptoprimitives.random.RandomService;
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
	static void setup() throws NoSuchAlgorithmException {
		messageDigest = MessageDigest.getInstance("SHA-256");
		hashLength = 32;
		hashService = new HashService(messageDigest);
		secureRandom = new SecureRandom();
		randomService = new RandomService();
	}

	@Test
	void testInstantiateWithNullHashFunctionThrows() {
		assertThrows(NullPointerException.class, () -> new HashService(null));
	}

	static Stream<Arguments> jsonFileArgumentProvider() {

		final List<TestParameters> parametersList = TestParameters.fromResource("/recursive-hash-sha256.json");

		return parametersList.stream().parallel().map(testParameters -> {

			final String messageDigest = testParameters.getContext().getJsonData("hash_function").getJsonNode().asText();

			final JsonData input = testParameters.getInput();

			Hashable[] values = readInput(input).toArray(new Hashable[] {});

			JsonData output = testParameters.getOutput();
			byte[] hash = output.get("value", byte[].class);

			return Arguments.of(messageDigest, values, hash, testParameters.getDescription());
		});
	}

	private static ImmutableList<Hashable> readInput(JsonData input) {
		List<Hashable> values = new ArrayList<>();
		if (input.getJsonNode().isArray()) {
			ArrayNode nodes = (ArrayNode) input.getJsonNode();
			for (JsonNode node : nodes) {
				JsonData nodeData = new JsonData(node);
				if (nodeData.getJsonNode().isArray()) {
					values.add(HashableList.from(readInput(nodeData)));
				} else {
					values.add(readValue(nodeData));
				}
			}
		} else {
			values.add(readValue(input));
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
	void testRecursiveHashWithRealValues(final String messageDigest, final Hashable[] input, final byte[] output, final String description)
			throws NoSuchAlgorithmException {
		HashService testHashService = new HashService(MessageDigest.getInstance(messageDigest));
		byte[] actual = testHashService.recursiveHash(input);
		assertArrayEquals(output, actual, String.format("assertion failed for: %s", description));
	}

	@Test
	void testRecursiveHashOfByteArrayReturnsHashOfByteArray() {
		byte[] bytes = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes);
		byte[] recursiveHash = hashService.recursiveHash(HashableByteArray.from(bytes));
		byte[] regularHash = messageDigest.digest(bytes);
		assertArrayEquals(regularHash, recursiveHash);
	}

	@Test
	void testRecursiveHashOfStringReturnsHashOfString() {
		String string = randomService.genRandomBase32String(TEST_INPUT_LENGTH);
		byte[] expected = messageDigest.digest(ConversionService.stringToByteArray(string));
		byte[] recursiveHash = hashService.recursiveHash(HashableString.from(string));
		assertArrayEquals(expected, recursiveHash);
	}

	@Test
	void testRecursiveHashOfBigIntegerValue10ReturnsSameHashOfInteger10() {
		BigInteger bigInteger = new BigInteger(2048, secureRandom);
		byte[] recursiveHash = hashService.recursiveHash(HashableBigInteger.from(bigInteger));
		byte[] regularHash = messageDigest.digest(ConversionService.integerToByteArray(bigInteger));
		assertArrayEquals(regularHash, recursiveHash);
	}

	@Test
	void testRecursiveHashOfNullThrows() {
		assertThrows(NullPointerException.class, () -> hashService.recursiveHash((Hashable) null));
	}

	@Test
	void testRecursiveHashOfListOfOneElementReturnsHashOfElement() {
		byte[] bytes = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes);
		ImmutableList<Hashable> list = ImmutableList.of(HashableByteArray.from(bytes));
		byte[] expected = messageDigest.digest(messageDigest.digest(bytes));
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

		HashableList list = hashableListOf(hashableBytes1, hashableBytes2);

		byte[] hash = hashService.recursiveHash(list);

		byte[] concatenation = new byte[hashLength * 2];
		System.arraycopy(messageDigest.digest(bytes1), 0, concatenation, 0, hashLength);
		System.arraycopy(messageDigest.digest(bytes2), 0, concatenation, hashLength, hashLength);
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
		HashableList list = hashableListOf(hashableBytes2, hashableBytes3);
		HashableList input = hashableListOf(hashableBytes1, list);

		byte[] hash = hashService.recursiveHash(input);

		byte[] subConcatenation = new byte[hashLength * 2];
		System.arraycopy(messageDigest.digest(bytes2), 0, subConcatenation, 0, hashLength);
		System.arraycopy(messageDigest.digest(bytes3), 0, subConcatenation, hashLength, hashLength);
		byte[] subHash = messageDigest.digest(subConcatenation);
		byte[] concatenation = new byte[hashLength * 2];
		System.arraycopy(messageDigest.digest(bytes1), 0, concatenation, 0, hashLength);
		System.arraycopy(subHash, 0, concatenation, hashLength, hashLength);
		byte[] expected = messageDigest.digest(concatenation);

		assertArrayEquals(expected, hash);
	}

	@Test
	void testRecursiveHashOfEmptyListThrows() {
		HashableList list = hashableListOf();
		assertThrows(IllegalArgumentException.class, () -> hashService.recursiveHash(list));
	}

	@Test
	void testRecursiveHashOfNestedEmptyListThrows() {
		HashableList emptyList = hashableListOf();
		HashableList list = hashableListOf(HashableBigInteger.from(BigInteger.ONE), emptyList);
		assertThrows(IllegalArgumentException.class, () -> hashService.recursiveHash(list));
	}

	@Test
	void testRecursiveHashWithVarargsGivesSameResultAsWithList() {
		HashableBigInteger first = genRandomHashableBigInteger();
		HashableString second = genRandomHashableString();
		HashableByteArray third = genRandomHashableByteArray();
		HashableList list = hashableListOf(third);
		HashableList input = hashableListOf(list, first, second);
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
		HashableList subList = hashableListOf(third, hashableSubSubList);
		HashableList input = hashableListOf(first, second, subList);

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(messageDigest.digest(ConversionService.integerToByteArray(first.toHashableForm())));
		outputStream.write(messageDigest.digest(second.toHashableForm()));
		byte[] expectedSubSubListHash = messageDigest.digest(outputStream.toByteArray());
		outputStream.close();

		ByteArrayOutputStream outputStream1 = new ByteArrayOutputStream();
		outputStream1.write(messageDigest.digest(ConversionService.stringToByteArray(third.toHashableForm())));
		outputStream1.write(expectedSubSubListHash);
		byte[] expectedSubListHash = messageDigest.digest(outputStream1.toByteArray());
		outputStream1.close();

		ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
		outputStream2.write(messageDigest.digest(ConversionService.integerToByteArray(first.toHashableForm())));
		outputStream2.write(messageDigest.digest(second.toHashableForm()));
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

	@Test
	void thereExistsCollisions() {
		HashableBigInteger num = HashableBigInteger.from(BigInteger.valueOf(33));
		HashableString string = HashableString.from("!");
		assertArrayEquals(hashService.recursiveHash(num), hashService.recursiveHash(string));
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

	private static class Split {
		final HashableByteArray start;
		final HashableByteArray end;

		Split(HashableByteArray start, HashableByteArray end) {
			this.start = start;
			this.end = end;
		}
	}

	@Test
	void testThatSimilarCharactersHashToDifferentValues() {
		HashableString first = HashableString.from("e");
		byte[] firstHash = hashService.recursiveHash(first);
		HashableString second = HashableString.from("é");
		byte[] secondHash = hashService.recursiveHash(second);
		assertNotEquals(firstHash, secondHash);
	}

	//Utilities
	static HashableList hashableListOf(Hashable... items) {
		return HashableList.from(ImmutableList.copyOf(items));
	}
}
