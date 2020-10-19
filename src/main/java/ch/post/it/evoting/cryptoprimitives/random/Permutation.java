/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.random;

import static com.google.common.base.Preconditions.checkArgument;

import java.util.Arrays;

/**
 * Represents a permutation of integers in the range [0, N).
 *
 * Instances of this class are immutable.
 */
public class Permutation {

	//valueMapping[i] represents the permutation of value i
	private final int[] valueMapping;
	private final int size;

	Permutation(final int[] valueMapping) {
		this.size = valueMapping.length;
		this.valueMapping = Arrays.copyOf(valueMapping, this.size);
	}

	/**
	 * Get the new value of value i under this permutation.
	 *
	 * @param i the value to get the permutation of, must be smaller than the size of this permutation.
	 * @return a value in the range [0, N)
	 */
	public int get(int i) {
		checkArgument(i >= 0);
		checkArgument(i < size);
		return this.valueMapping[i];
	}

	/**
	 * @return the size of this permutation, i.e. the upperbound of values represented in this permutation.
	 */
	public int getSize() {
		return this.size;
	}
}
