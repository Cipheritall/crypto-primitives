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

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.internal.mixnet.MatrixUtils;

class MatrixUtilsTest {

	@Test
	@DisplayName("invalid N throws IllegalArgumentException")
	void getMatrixDimensionsInvalidN() {
		assertThrows(IllegalArgumentException.class, () -> MatrixUtils.getMatrixDimensions(0));
		assertThrows(IllegalArgumentException.class, () -> MatrixUtils.getMatrixDimensions(-1));
	}

	@Test
	@DisplayName("valid N gives expected dimensions")
	void getMatrixDimensionsTest() {
		assertAll(
				() -> assertArrayEquals(new int[] { 1, 2 }, MatrixUtils.getMatrixDimensions(2)),
				() -> assertArrayEquals(new int[] { 1, 3 }, MatrixUtils.getMatrixDimensions(3)),
				() -> assertArrayEquals(new int[] { 3, 4 }, MatrixUtils.getMatrixDimensions(12)),
				() -> assertArrayEquals(new int[] { 3, 6 }, MatrixUtils.getMatrixDimensions(18)),
				() -> assertArrayEquals(new int[] { 1, 23 }, MatrixUtils.getMatrixDimensions(23)),
				() -> assertArrayEquals(new int[] { 5, 5 }, MatrixUtils.getMatrixDimensions(25)),
				() -> assertArrayEquals(new int[] { 3, 9 }, MatrixUtils.getMatrixDimensions(27))
		);

	}
}
