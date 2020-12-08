package ch.post.it.evoting.cryptoprimitives;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.fromByteArray;
import static ch.post.it.evoting.cryptoprimitives.ConversionService.toByteArray;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

public class ConversionServiceTest {

	private static Random random;

	@BeforeAll
	static void setUp() {
		random = new SecureRandom();
	}

	//Test BigInteger to ByteArray conversion
	@Test
	void testConversionOfNullBigIntegerToByteArrayThrows(){
		assertThrows(NullPointerException.class, () -> toByteArray((BigInteger) null));
	}

	@Test
	void testConversionOfZeroBigIntegerIsOneZeroByte() {
		BigInteger zero = BigInteger.ZERO;
		byte[] expected = new byte[]{0};
		byte[] converted = toByteArray(zero);
		assertArrayEquals(expected, converted);
	}

	@Test
	void testConversionOf256BigIntegerIsTwoBytes(){
		BigInteger value = BigInteger.valueOf(256);
		byte[] expected = new byte[]{1, 0};
		byte[] converted = toByteArray(value);
		assertArrayEquals(expected, converted);
	}

	@Test
	void testConversionOfIntegerMaxValuePlusOneIsCorrect(){
		BigInteger value = BigInteger.valueOf(Integer.MAX_VALUE).add(BigInteger.ONE);
		byte[] expected = new byte[]{ (byte) 0b10000000, 0, 0, 0};
		byte[] converted = toByteArray(value);
		assertArrayEquals(expected, converted);
	}

	@Test
	void testOfNegativeBigIntegerThrows() {
		BigInteger value = BigInteger.valueOf(-1);
		assertThrows(IllegalArgumentException.class, () -> toByteArray(value));
	}

	//Test byte array to BigInteger conversion
	@Test
	void testConversionOfNullToBigIntegerThrows() {
		assertThrows(NullPointerException.class, () -> fromByteArray((byte[]) null));
	}

	@Test
	void testConversionOfByteArrayWithLeading1ToBigIntegerIsPositive(){
		byte[] bytes = new byte[]{(byte) 0x80};
		BigInteger converted = fromByteArray(bytes);
		assertTrue(converted.compareTo(BigInteger.ZERO) > 0);
	}

	@Test
	void testConversionOf256ByteArrayRepresentationIs256() {
		byte[] bytes = new byte[]{1, 0};
		BigInteger converted = fromByteArray(bytes);
		assertEquals(converted.compareTo(BigInteger.valueOf(256)), 0);
	}

	//Cyclic test BigInteger to byte array and back
	@RepeatedTest(10)
	void testRandomBigIntegerToByteArrayAndBackIsOriginalValue() {
		int size = random.nextInt(32);
		BigInteger value = new BigInteger(size, random);
		BigInteger cycledValue = fromByteArray(toByteArray(value));
		assertEquals(value, cycledValue);
	}
}
