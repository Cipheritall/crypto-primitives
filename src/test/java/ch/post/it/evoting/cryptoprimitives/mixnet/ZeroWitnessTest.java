/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

@DisplayName("A ZeroWitness")
class ZeroWitnessTest {

	private static final SecureRandom secureRandom = new SecureRandom();

	private static ZqGroup zqGroup;
	private static ZqGroupGenerator zqGroupGenerator;

	private int n;
	private int m;
	private SameGroupMatrix<ZqElement, ZqGroup> matrixA;
	private SameGroupMatrix<ZqElement, ZqGroup> matrixB;
	private SameGroupVector<ZqElement, ZqGroup> exponentsR;
	private SameGroupVector<ZqElement, ZqGroup> exponentsS;

	@BeforeAll
	static void setUpAll() {
		zqGroup = GroupTestData.getZqGroup();
		zqGroupGenerator = new ZqGroupGenerator(zqGroup);
	}

	@BeforeEach
	void setUp() {
		n = secureRandom.nextInt(10) + 1;
		m = secureRandom.nextInt(10) + 1;

		matrixA = zqGroupGenerator.genRandomZqElementMatrix(n, m);
		matrixB = zqGroupGenerator.genRandomZqElementMatrix(n, m);
		exponentsR = zqGroupGenerator.genRandomZqElementVector(m);
		exponentsS = zqGroupGenerator.genRandomZqElementVector(m);
	}

	@Test
	@DisplayName("constructed with valid parameters works as expected")
	void construct() {
		final ZeroWitness zeroWitness = new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS);

		assertEquals(zqGroup, zeroWitness.getMatrixA().getGroup());
		assertEquals(zqGroup, zeroWitness.getMatrixB().getGroup());
		assertEquals(zqGroup, zeroWitness.getExponentsR().getGroup());
		assertEquals(zqGroup, zeroWitness.getExponentsS().getGroup());
	}

	@Test
	@DisplayName("constructed with empty matrices and vectors works as expected")
	void constructEmptyParams() {
		final SameGroupMatrix<ZqElement, ZqGroup> emptyMatrixA = SameGroupMatrix.fromRows(Collections.emptyList());
		final SameGroupMatrix<ZqElement, ZqGroup> emptyMatrixB = SameGroupMatrix.fromRows(Collections.emptyList());
		final SameGroupVector<ZqElement, ZqGroup> emptyExponentsR = SameGroupVector.of();
		final SameGroupVector<ZqElement, ZqGroup> emptyExponentsS = SameGroupVector.of();

		assertDoesNotThrow(() -> new ZeroWitness(emptyMatrixA, emptyMatrixB, emptyExponentsR, emptyExponentsS));
	}

	@Test
	@DisplayName("constructed with any null parameter throws IllegalArgumentException")
	void constructNullParams() {
		final SameGroupMatrix<ZqElement, ZqGroup> emptyMatrixA = SameGroupMatrix.fromRows(Collections.emptyList());
		final SameGroupMatrix<ZqElement, ZqGroup> emptyMatrixB = SameGroupMatrix.fromRows(Collections.emptyList());
		final SameGroupVector<ZqElement, ZqGroup> emptyExponentsR = SameGroupVector.of();
		final SameGroupVector<ZqElement, ZqGroup> emptyExponentsS = SameGroupVector.of();

		assertAll(
				() -> assertThrows(NullPointerException.class, () -> new ZeroWitness(null, matrixB, exponentsR, exponentsS)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroWitness(matrixA, null, exponentsR, exponentsS)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroWitness(matrixA, matrixB, null, exponentsS)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroWitness(matrixA, matrixB, exponentsR, null)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroWitness(null, emptyMatrixB, emptyExponentsR, emptyExponentsS)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroWitness(emptyMatrixA, null, emptyExponentsR, emptyExponentsS)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroWitness(emptyMatrixA, emptyMatrixB, null, emptyExponentsS)),
				() -> assertThrows(NullPointerException.class, () -> new ZeroWitness(emptyMatrixA, emptyMatrixB, emptyExponentsR, null))
		);
	}

	@Test
	@DisplayName("constructed with matrices of different size throws IllegalArgumentException")
	void constructDiffSizeMatrices() {
		final SameGroupMatrix<ZqElement, ZqGroup> additionalRowMatrix = zqGroupGenerator.genRandomZqElementMatrix(n + 1, m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(additionalRowMatrix, matrixB, exponentsR, exponentsS));
		assertEquals("The two matrices must have the same number of rows.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with exponents of different size throws IllegalArgumentException")
	void constructDiffSizeExponents() {
		final SameGroupVector<ZqElement, ZqGroup> additionalElemExponentsR = exponentsR.append(ZqElement.create(BigInteger.ONE, zqGroup));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, additionalElemExponentsR, exponentsS));
		assertEquals("The exponents vector must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with exponents of size not equal to number of matrices rows throws IllegalArgumentException")
	void constructSizeExponentsNotEqualMatricesRows() {
		final SameGroupVector<ZqElement, ZqGroup> additionalElemExponentsR = exponentsR.append(ZqElement.create(BigInteger.ONE, zqGroup));
		final SameGroupVector<ZqElement, ZqGroup> additionalElemExponentsS = exponentsS.append(ZqElement.create(BigInteger.ONE, zqGroup));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, additionalElemExponentsR, additionalElemExponentsS));
		assertEquals("The exponents vectors size must be the number of columns of the matrices.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with matrices with different number of columns throws IllegalArgumentException")
	void constructMatricesDiffColNumber() {
		final SameGroupVector<ZqElement, ZqGroup> newColumn = zqGroupGenerator.genRandomZqElementVector(n);
		final SameGroupMatrix<ZqElement, ZqGroup> additionalColMatrixA = matrixA.appendColumn(newColumn);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(additionalColMatrixA, matrixB, exponentsR, exponentsS));
		assertEquals("The two matrices must have the same number of columns.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with matrices from different group throws IllegalArgumentException")
	void constructMatricesDiffGroup() {
		// Get another group.
		final ZqGroup otherZqGroup = GroupTestData.getDifferentZqGroup(zqGroup);
		final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);

		final SameGroupMatrix<ZqElement, ZqGroup> otherZqGroupMatrix = otherZqGroupGenerator.genRandomZqElementMatrix(n, m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(otherZqGroupMatrix, matrixB, exponentsR, exponentsS));
		assertEquals("The matrices are not from the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with exponents from different group throws IllegalArgumentException")
	void constructExponentsDiffGroup() {
		// Get another group.
		final ZqGroup otherZqGroup = GroupTestData.getDifferentZqGroup(zqGroup);
		final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);

		final SameGroupVector<ZqElement, ZqGroup> otherZqGroupExponents = otherZqGroupGenerator.genRandomZqElementVector(m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, otherZqGroupExponents, exponentsS));
		assertEquals("The exponents are not from the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with matrices and exponents from different group throws IllegalArgumentException")
	void constructMatricesExponentsDiffGroup() {
		// Get another group.
		final ZqGroup otherZqGroup = GroupTestData.getDifferentZqGroup(zqGroup);
		final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);

		final SameGroupVector<ZqElement, ZqGroup> otherZqGroupExponentsR = otherZqGroupGenerator.genRandomZqElementVector(m);
		final SameGroupVector<ZqElement, ZqGroup> otherZqGroupExponentsS = otherZqGroupGenerator.genRandomZqElementVector(m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, otherZqGroupExponentsR, otherZqGroupExponentsS));
		assertEquals("The matrices and exponents are not from the same group.", exception.getMessage());
	}
}