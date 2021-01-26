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
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

@DisplayName("A ZeroWitness")
class ZeroWitnessTest {

	private static final SecureRandom secureRandom = new SecureRandom();

	private static ZqGroup zqGroup;
	private static ZqGroupGenerator zqGroupGenerator;

	private int m;
	private int n;
	private List<List<ZqElement>> matrixA;
	private List<List<ZqElement>> matrixB;
	private List<ZqElement> exponentsR;
	private List<ZqElement> exponentsS;

	@BeforeAll
	static void setUpAll() {
		// GqGroup and corresponding ZqGroup set up.
		final GqGroup gqGroup = GqGroupTestData.getGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		zqGroupGenerator = new ZqGroupGenerator(zqGroup);
	}

	@BeforeEach
	void setUp() {
		m = secureRandom.nextInt(10) + 1;
		n = secureRandom.nextInt(10) + 1;

		matrixA = zqGroupGenerator.generateRandomZqElementMatrix(n, m);
		matrixB = zqGroupGenerator.generateRandomZqElementMatrix(n, m);
		exponentsR = zqGroupGenerator.generateRandomZqElementList(m);
		exponentsS = zqGroupGenerator.generateRandomZqElementList(m);
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
		final List<List<ZqElement>> emptyMatrixA = Collections.emptyList();
		final List<List<ZqElement>> emptyMatrixB = Collections.emptyList();
		final List<ZqElement> emptyExponentsR = Collections.emptyList();
		final List<ZqElement> emptyExponentsS = Collections.emptyList();

		assertDoesNotThrow(() -> new ZeroWitness(emptyMatrixA, emptyMatrixB, emptyExponentsR, emptyExponentsS));
	}

	@Test
	@DisplayName("constructed with any null parameter throws IllegalArgumentException")
	void constructNullParams() {
		final List<List<ZqElement>> emptyMatrixA = Collections.emptyList();
		final List<List<ZqElement>> emptyMatrixB = Collections.emptyList();
		final List<ZqElement> emptyExponentsR = Collections.emptyList();
		final List<ZqElement> emptyExponentsS = Collections.emptyList();

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
		matrixA.add(zqGroupGenerator.generateRandomZqElementList(m));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS));
		assertEquals("The two matrices must have the same number of rows.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with exponents of different size throws IllegalArgumentException")
	void constructDiffSizeExponents() {
		exponentsR.add(ZqElement.create(BigInteger.ONE, zqGroup));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS));
		assertEquals("The exponents vector must have the same size.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with exponents of size not equal to number of matrices rows throws IllegalArgumentException")
	void constructSizeExponentsNotEqualMatricesRows() {
		exponentsR.add(ZqElement.create(BigInteger.ONE, zqGroup));
		exponentsS.add(ZqElement.create(BigInteger.ONE, zqGroup));

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, exponentsR, exponentsS));
		assertEquals("The exponents vectors size must be the number of columns of the matrices.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with matrices with different number of columns throws IllegalArgumentException")
	void constructMatricesDiffColNumber() {
		final List<List<ZqElement>> biggerMatrixA = zqGroupGenerator.generateRandomZqElementMatrix(n, m + 1);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(biggerMatrixA, matrixB, exponentsR, exponentsS));
		assertEquals("The two matrices must have the same number of columns.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with matrices from different group throws IllegalArgumentException")
	void constructMatricesDiffGroup() {
		// Get another group.
		final ZqGroup otherZqGroup = zqGroupGenerator.otherGroup();
		final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);

		final List<List<ZqElement>> otherZqGroupMatrix = otherZqGroupGenerator.generateRandomZqElementMatrix(n, m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(otherZqGroupMatrix, matrixB, exponentsR, exponentsS));
		assertEquals("The matrices are not from the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with exponents from different group throws IllegalArgumentException")
	void constructExponentsDiffGroup() {
		// Get another group.
		final ZqGroup otherZqGroup = zqGroupGenerator.otherGroup();
		final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);

		final List<ZqElement> otherZqGroupExponents = otherZqGroupGenerator.generateRandomZqElementList(m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, otherZqGroupExponents, exponentsS));
		assertEquals("The exponents are not from the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("constructed with matrices and exponents from different group throws IllegalArgumentException")
	void constructMatricesExponentsDiffGroup() {
		// Get another group.
		final ZqGroup otherZqGroup = zqGroupGenerator.otherGroup();
		final ZqGroupGenerator otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);

		final List<ZqElement> otherZqGroupExponentsR = otherZqGroupGenerator.generateRandomZqElementList(m);
		final List<ZqElement> otherZqGroupExponentsS = otherZqGroupGenerator.generateRandomZqElementList(m);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ZeroWitness(matrixA, matrixB, otherZqGroupExponentsR, otherZqGroupExponentsS));
		assertEquals("The matrices and exponents are not from the same group.", exception.getMessage());
	}
}