/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupMatrix;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

class ProductWitnessTest {

	private static final int MATRIX_BOUND = 10;
	private static final SecureRandom secureRandom = new SecureRandom();

	private ZqGroupGenerator generator;
	private int n;
	private int m;
	private ZqGroup zqGroup;
	private SameGroupMatrix<ZqElement, ZqGroup> matrix;
	private SameGroupVector<ZqElement, ZqGroup> exponents;

	@BeforeEach
	void setup() {
		n = secureRandom.nextInt(MATRIX_BOUND) + 1;
		m = secureRandom.nextInt(MATRIX_BOUND) + 1;
		GqGroup gqGroup = GqGroupTestData.getGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		generator = new ZqGroupGenerator(zqGroup);
		matrix = generator.generateRandomZqElementMatrix(n, m);
		exponents = generator.generateRandomZqElementVector(m);
	}

	@Test
	@DisplayName("Instantiating a ProductWitness with null arguments throws a NullPointerException")
	void constructProductWitnessWithNull() {
		assertThrows(NullPointerException.class, () -> new ProductWitness(matrix, null));
		assertThrows(NullPointerException.class, () -> new ProductWitness(null, exponents));
	}

	@Test
	@DisplayName("Instantiating a ProductWitness with exponents longer than the number of matrix columns throws an IllegalArgumentException")
	void constructProductWitnessWithTooLongExponents() {
		SameGroupVector<ZqElement, ZqGroup> tooLongExponents = generator.generateRandomZqElementVector(m + 1);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new ProductWitness(matrix, tooLongExponents));
		assertEquals("The number of columns in the matrix must be equal to the number of exponents.", exception.getMessage());
	}

	@Test
	@DisplayName("Instantiating a ProductWitness with the matrix and the exponents from different groups throws an IllegalArgumentException")
	void constructProductWitnessWithMatrixAndExponentsFromDifferentGroup() {
		ZqGroup differentZqGroup = new ZqGroupGenerator(zqGroup).otherGroup();
		ZqGroupGenerator differentGenerator = new ZqGroupGenerator(differentZqGroup);
		SameGroupVector<ZqElement, ZqGroup> differentExponents = differentGenerator.generateRandomZqElementVector(m);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new ProductWitness(matrix, differentExponents));
		assertEquals("The matrix and the exponents must belong to the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("The equals method returns true if and only if the matrix and exponents are the same")
	void testEquals() {
		ProductWitness witness1 = new ProductWitness(matrix, exponents);
		ProductWitness witness2 = new ProductWitness(matrix, exponents);

		ZqElement one = ZqElement.create(BigInteger.ONE, zqGroup);
		List<ZqElement> exponentsValues = exponents.stream().collect(Collectors.toCollection(ArrayList::new));
		ZqElement first = exponentsValues.get(0);
		first = first.add(one);
		exponentsValues.set(0, first);
		SameGroupVector<ZqElement, ZqGroup> differentExponents = new SameGroupVector<>(exponentsValues);
		ProductWitness witness3 = new ProductWitness(matrix, differentExponents);

		List<List<ZqElement>> matrixValues = IntStream.range(0, m)
				.mapToObj(j -> matrix.getColumn(j).stream().collect(Collectors.toCollection(ArrayList::new)))
				.collect(Collectors.toCollection(ArrayList::new));
		first = matrixValues.get(0).get(0);
		first = first.add(one);
		matrixValues.get(0).set(0, first);
		SameGroupMatrix<ZqElement, ZqGroup> differentMatrix = SameGroupMatrix.fromColumns(matrixValues);
		ProductWitness witness4 = new ProductWitness(differentMatrix, exponents);

		assertAll(
				() -> assertEquals(witness1, witness2),
				() -> assertNotEquals(witness1, witness3),
				() -> assertNotEquals(witness1, witness4),
				() -> assertNotEquals(witness3, witness4)
		);
	}
}