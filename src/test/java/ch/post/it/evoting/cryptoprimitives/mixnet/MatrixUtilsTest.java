/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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