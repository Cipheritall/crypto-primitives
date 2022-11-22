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
package ch.post.it.evoting.cryptoprimitives.internal.mixnet;

import static com.google.common.base.Preconditions.checkArgument;

public class MatrixUtils {

	private MatrixUtils() {
		// Intentionally left blank.
	}

	/**
	 * Computes the size-optimal number of rows and columns for a given vector size {@code N}. The dimensions are size-optimal when they are as close
	 * as possible to the dimensions of a square matrix, resulting in the smallest size of the shuffle argument.
	 *
	 * @param vectorSize N, the vector size to decompose into size-optimal matrix dimensions. Must be greater than or equal to 2.
	 * @return an array [m, n] with m the number of rows, n the number of columns and m x n = N, where m <= n.
	 */
	public static int[] getMatrixDimensions(final int vectorSize) {
		final int N = vectorSize;
		checkArgument(N >= 2, "The size to decompose must be greater than or equal to 2.");

		int m = 1;
		int n = N;
		for (int i = (int) Math.floor(Math.sqrt(N)); i > 1; i--) {
			if (N % i == 0) {
				m = i;
				n = N / i;
				break;
			}
		}

		return new int[] { m, n };
	}

}
