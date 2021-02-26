/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;

import java.util.function.LongFunction;

class MatrixUtils {

	private MatrixUtils() {
		// Intentionally left blank.
	}

	/**
	 * Computes the size-optimal number of rows and columns for a given vector size {@code N}. The dimensions are size-optimal when they are as close
	 * as possible to the dimensions of a square matrix, resulting in the smallest size of the shuffle argument.
	 *
	 * @param N the vector size to decompose into size-optimal matrix dimensions. Must be greater than or equal to 2.
	 * @return an array [m, n] with m the number of rows, n the number of columns and m x n = N.
	 */
	static int[] getMatrixDimensions(final int N) {
		checkArgument(N >= 2, "The size to decompose must be greater than or equal to 2.");

		final LongFunction<Integer> floorSquareRoot = x -> (int) Math.floor(Math.sqrt(x));

		int m = 1;
		int n = N;
		for (int i = floorSquareRoot.apply(N); i > 1; i--) {
			if (N % i == 0) {
				m = i;
				n = N / i;
				break;
			}
		}

		return new int[] { m, n };
	}

}
