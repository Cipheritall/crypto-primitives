package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

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

class HadamardWitnessTest {

	private static final int MATRIX_BOUNDS = 10;
	private static final SecureRandom secureRandom = new SecureRandom();

	private int n;
	private int m;
	private ZqGroupGenerator zqGenerator;
	private ZqGroupGenerator otherZqGenerator;
	private SameGroupMatrix<ZqElement, ZqGroup> matrix;
	private SameGroupVector<ZqElement, ZqGroup> vector;
	private SameGroupVector<ZqElement, ZqGroup> exponents;
	private ZqElement randomness;

	@BeforeEach
	void setup() {
		n = secureRandom.nextInt(MATRIX_BOUNDS) + 1;
		m = secureRandom.nextInt(MATRIX_BOUNDS) + 1;

		// GqGroup and corresponding ZqGroup set up.
		final GqGroup gqGroup = GqGroupTestData.getGroup();
		ZqGroup zqGroup = ZqGroup.sameOrderAs(gqGroup);
		final GqGroup otherGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
		ZqGroup otherZqGroup = ZqGroup.sameOrderAs(otherGqGroup);

		zqGenerator = new ZqGroupGenerator(zqGroup);
		otherZqGenerator = new ZqGroupGenerator(otherZqGroup);

		matrix = zqGenerator.generateRandomZqElementMatrix(n, m);
		vector = zqGenerator.generateRandomZqElementVector(n);
		exponents = zqGenerator.generateRandomZqElementVector(m);
		randomness = zqGenerator.genZqElementMember();
	}

	@Test
	@DisplayName("Constructing a Hadamard witness with valid input does not throw")
	void constructWitness() {
		assertDoesNotThrow(() -> new HadamardWitness(matrix, vector, exponents, randomness));
	}

	@Test
	@DisplayName("Constructing a Hadamard witness with null arguments should throw a NullPointerException")
	void constructWitnessWithNullArguments() {
		assertAll(
				() -> assertThrows(NullPointerException.class, () -> new HadamardWitness(null, vector, exponents, randomness)),
				() -> assertThrows(NullPointerException.class, () -> new HadamardWitness(matrix, null, exponents, randomness)),
				() -> assertThrows(NullPointerException.class, () -> new HadamardWitness(matrix, vector, null, randomness)),
				() -> assertThrows(NullPointerException.class, () -> new HadamardWitness(matrix, vector, exponents, null))
		);

	}

	@Test
	@DisplayName("Constructing a Hadamard witness with matrix columns and vector of different sizes should throw")
	void constructWitnessWithMatrixColumnsAndVectorOfDifferentSizes() {
		vector = zqGenerator.generateRandomZqElementVector(n + 1);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new HadamardWitness(matrix, vector, exponents, randomness));
		assertEquals("The matrix A must have the same number of rows as the vector b has elements.", exception.getMessage());
	}

	@Test
	@DisplayName("Constructing a Hadamard witness with matrix and vector from different groups should throw")
	void constructWitnessWithMatrixAndVectorFromDifferentGroups() {
		vector = otherZqGenerator.generateRandomZqElementVector(n);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new HadamardWitness(matrix, vector, exponents, randomness));
		assertEquals("The matrix A and the vector b must have the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("Constructing a Hadamard witness with matrix rows and exponents of different sizes should throw")
	void constructWitnessWithMatrixRowsAndExponentsOfDifferentSizes() {
		exponents = zqGenerator.generateRandomZqElementVector(m + 1);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new HadamardWitness(matrix, vector, exponents, randomness));
		assertEquals("The matrix A must have the same number of columns as the exponents r have elements.", exception.getMessage());
	}

	@Test
	@DisplayName("Constructing a Hadamard witness with matrix and exponents from different groups should throw")
	void constructWitnessWithMatrixAndExponentsFromDifferentGroups() {
		exponents = otherZqGenerator.generateRandomZqElementVector(m);
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new HadamardWitness(matrix, vector, exponents, randomness));
		assertEquals("The matrix A and the exponents r must have the same group.", exception.getMessage());
	}

	@Test
	@DisplayName("Constructing a Hadamard witness with exponents and randomness from different groups should throw")
	void constructWitnessWithExponentsAndRandomnessFromDifferentGroups() {
		randomness = otherZqGenerator.genZqElementMember();
		Exception exception = assertThrows(IllegalArgumentException.class, () -> new HadamardWitness(matrix, vector, exponents, randomness));
		assertEquals("The exponents r and the exponent s must have the same group.", exception.getMessage());
	}
}