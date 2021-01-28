/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.integerToByteArray;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.random.RandomService;

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
	void testInstantiateWithNullHashFunctionThrows(){
		assertThrows(NullPointerException.class, () -> new HashService(null));
	}

	@Test
	void testRecursiveHashOfByteArrayReturnsHashOfByteArray() {
		byte[] bytes = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes);
		byte[] recursiveHash = hashService.recursiveHash(bytes);
		byte[] regularHash = messageDigest.digest(bytes);
		assertArrayEquals(regularHash, recursiveHash);
	}

	@Test
	void testRecursiveHashOfStringReturnsHashOfString() {
		String string = randomService.genRandomBase32String(TEST_INPUT_LENGTH);
		byte[] expected = messageDigest.digest(integerToByteArray(string));
		byte[] recursiveHash = hashService.recursiveHash(string);
		assertArrayEquals(expected, recursiveHash);
	}

	@Test
	void testRecursiveHashOfBigIntegerValue10ReturnsSameHashOfInteger10() {
		BigInteger bigInteger = new BigInteger(2048, secureRandom);
		byte[] recursiveHash = hashService.recursiveHash(bigInteger);
		byte[] regularHash = messageDigest.digest(ConversionService.integerToByteArray(bigInteger));
		assertArrayEquals(regularHash, recursiveHash);
	}

	@Test
	void testRecursiveHashOfInvalidTypeThrow(){
		int integer = 5;
		assertThrows(IllegalArgumentException.class, () -> hashService.recursiveHash(integer));
	}

	@Test
	void testRecursiveHashOfNullObjectThrows(){
		assertThrows(IllegalArgumentException.class, () -> hashService.recursiveHash((Object) null));
	}

	@Test
	void testRecursiveHashOfNullThrows() {
		assertThrows(NullPointerException.class, () -> hashService.recursiveHash(null));
	}

	@Test
	void testRecursiveHashOfListOfOneElementReturnsHashOfElement(){
		byte[] bytes = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes);
		List<?> list = Collections.singletonList(bytes);
		byte[] expected = messageDigest.digest(messageDigest.digest(bytes));
		byte[] hash = hashService.recursiveHash(list);
		assertArrayEquals(expected, hash);
	}

	@Test
	void testRecursiveHashOfTwoByteArraysReturnsHashOfConcatenatedIndividualHashes(){
		byte[] bytes1 = new byte[TEST_INPUT_LENGTH];
		byte[] bytes2 = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes1);
		secureRandom.nextBytes(bytes2);
		List<?> list = Arrays.asList(bytes1, bytes2);

		byte[] hash = hashService.recursiveHash(list);

		byte[] concatenation = new byte[hashLength * 2];
		System.arraycopy(messageDigest.digest(bytes1), 0, concatenation, 0, hashLength);
		System.arraycopy(messageDigest.digest(bytes2), 0, concatenation, hashLength, hashLength);
		byte[] expected = messageDigest.digest(concatenation);

		assertArrayEquals(expected, hash);
	}

	@Test
	void testRecursiveHashOfAByteArrayAndAListOfTwoByteArraysReturnsExpectedHash(){
		byte[] bytes1 = new byte[TEST_INPUT_LENGTH];
		byte[] bytes2 = new byte[TEST_INPUT_LENGTH];
		byte[] bytes3 = new byte[TEST_INPUT_LENGTH];
		secureRandom.nextBytes(bytes1);
		secureRandom.nextBytes(bytes2);
		secureRandom.nextBytes(bytes3);
		List<?> list = Arrays.asList(bytes2, bytes3);
		Object input = Arrays.asList(bytes1, list);

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
		List<?> list = Collections.emptyList();
		assertThrows(IllegalArgumentException.class, () -> hashService.recursiveHash(list));
	}

	@Test
	void testRecursiveHashOfNestedEmptyListThrows() {
		List<?> emptyList = Collections.emptyList();
		List<?> list = Arrays.asList(1, emptyList);
		assertThrows(IllegalArgumentException.class, () -> hashService.recursiveHash(list));
	}

	@Test
	void testRecursiveHashWithVarargsGivesSameResultAsWithList() {
		Object first = genRandomLeafObject(BigInteger.class);
		Object second = genRandomLeafObject(String.class);
		Object third = genRandomLeafObject(byte[].class);
		List<?> list = Collections.singletonList(third);
		List<?> input = Arrays.asList(list, first, second);
		byte[] varargsHash = hashService.recursiveHash(list, first, second);
		byte[] listHash = hashService.recursiveHash(input);
		assertArrayEquals(listHash, varargsHash);
	}

	@Test
	void testRecursiveHashWithNestedListAndSpecificValues() throws IOException {
		BigInteger first = (BigInteger) genRandomLeafObject(BigInteger.class);
		byte[] second = (byte[]) genRandomLeafObject(byte[].class);
		String third = (String) genRandomLeafObject(String.class);
		List<Object> subSubList = new LinkedList<>();
		subSubList.add(first);
		subSubList.add(second);
		List<Object> subList = Arrays.asList(third, subSubList);
		List<Object> input = Arrays.asList(first, second, subList);

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(messageDigest.digest(ConversionService.integerToByteArray(first)));
		outputStream.write(messageDigest.digest(second));
		byte[] expectedSubSubListHash = messageDigest.digest(outputStream.toByteArray());
		outputStream.close();

		ByteArrayOutputStream outputStream1 = new ByteArrayOutputStream();
		outputStream1.write(messageDigest.digest(integerToByteArray(third)));
		outputStream1.write(expectedSubSubListHash);
		byte[] expectedSubListHash = messageDigest.digest(outputStream1.toByteArray());
		outputStream1.close();

		ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
		outputStream2.write(messageDigest.digest(ConversionService.integerToByteArray(first)));
		outputStream2.write(messageDigest.digest(second));
		outputStream2.write(expectedSubListHash);
		byte[] expectedHash = messageDigest.digest(outputStream2.toByteArray());
		outputStream2.close();

		byte[] hash = hashService.recursiveHash(input);

		assertArrayEquals(expectedHash, hash);
	}

	private Object genRandomLeafObject(Class<?> clazz) {
		if (clazz.equals(BigInteger.class)){
			return new BigInteger(50 , secureRandom);
		} else if (clazz.equals(byte[].class)){
			int size = secureRandom.nextInt(500);
			byte[] bytes = new byte[size];
			secureRandom.nextBytes(bytes);
			return bytes;
		} else if (clazz.equals(String.class)){
			return randomService.genRandomBase32String(TEST_INPUT_LENGTH);
		} else {
			throw new UnsupportedOperationException();
		}
	}

	@Test
	void thereExistsCollisions() {
		BigInteger num = BigInteger.valueOf(33);
		String string = "!";
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
		} while (Arrays.equals(second.start, first.start));

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
		return new Split(first, second);
	}

	private static class Split {
		final byte[] start;
		final byte[] end;

		Split(byte[] start, byte[] end) {
			this.start = start;
			this.end = end;
		}
	}

	@Test
	void testThatSimilarCharactersHashToDifferentValues() {
		String first = "e";
		byte[] firstHash = hashService.recursiveHash(first);
		String second = "é";
		byte[] secondHash = hashService.recursiveHash(second);
		assertNotEquals(firstHash, secondHash);
	}
}
