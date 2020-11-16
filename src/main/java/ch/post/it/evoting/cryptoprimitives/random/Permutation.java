/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.random;

import static com.google.common.base.Preconditions.checkArgument;

import java.math.BigInteger;
import java.util.stream.IntStream;

/**
 * Represents a permutation integers in the range [0, N) .
 */
public class Permutation {

	static RandomService randomService = new RandomService();

	//valueMapping[i] represents the permutation of value i
	private final int[] valueMapping;
	private final int size;

	private Permutation(final int[] valueMapping) {
		this.valueMapping = valueMapping;
		this.size = valueMapping.length;
	}

	/**
	 * Generate a permutation of integers [0, size)
	 *
	 * @param size N, the positive number of values being permutted
	 * @return a Permutation object representing an individual permutation
	 */
	public static Permutation genPermutation(int size) {
		checkArgument(size > 0);

		int[] psi = IntStream.range(0, size).toArray();
		for (int i = 0; i < size; i++) {
			int offset = randomService.genRandomInteger(BigInteger.valueOf((long) size - i)).intValueExact();
			int tmp = psi[i];
			psi[i] = psi[i + offset];
			psi[i + offset] = tmp;
		}

		return new Permutation(psi);
	}

	/**
	 * Get the new value of value i under this permutation.
	 *
	 * @param i the value to get the permutation of, must be smaller than the size of this permutation.
	 * @return a value in the range [0, N)
	 */
	int get(int i) {
		checkArgument(i >= 0);
		checkArgument(i < size);
		return this.valueMapping[i];
	}

	/**
	 * @return the size of this permutation, i.e. the upperbound of values represented in this permutation.
	 */
	int getSize() {
		return this.size;
	}
}
