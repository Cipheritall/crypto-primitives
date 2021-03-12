/*
 * Copyright 2021 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.TestGroupSetup;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;

@DisplayName("A Product Argument")
class ProductArgumentTest extends TestGroupSetup {

	private static final int UPPER_BOUND = 10;

	private static int m;
	private static int n;
	private static ArgumentGenerator argumentGenerator;

	private static GqElement commitmentB;
	private static SingleValueProductArgument singleValueProductArgument;
	private static HadamardArgument hadamardArgument;

	@BeforeAll
	static void setUpAll() {
		m = secureRandom.nextInt(UPPER_BOUND) + 1;
		n = secureRandom.nextInt(UPPER_BOUND - 1) + 2;
		argumentGenerator = new ArgumentGenerator(gqGroup);

		final ProductArgument productArgument = argumentGenerator.genProductArgument(m, n);

		commitmentB = productArgument.getCommitmentB();
		hadamardArgument = productArgument.getHadamardArgument();
		singleValueProductArgument = productArgument.getSingleValueProductArgument();
	}

	@Test
	@DisplayName("constructed with null arguments throws a NullPointerException")
	void constructMultiValueProductArgumentWithNullArguments() {
		assertAll(
				() -> assertThrows(NullPointerException.class,
						() -> new ProductArgument(null, hadamardArgument, singleValueProductArgument)),
				() -> assertThrows(NullPointerException.class, () -> new ProductArgument(commitmentB, null, singleValueProductArgument)),
				() -> assertThrows(NullPointerException.class, () -> new ProductArgument(commitmentB, hadamardArgument, null)),
				() -> assertThrows(NullPointerException.class, () -> new ProductArgument(null))
		);
	}

	@Test
	@DisplayName("constructed with commitmentB from different group throws IllegalArgumentException")
	void constructWithDiffGroupB() {
		final GqElement otherGroupCommitmentB = otherGqGroupGenerator.genMember();

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ProductArgument(otherGroupCommitmentB, hadamardArgument, singleValueProductArgument));
		assertEquals("The commitment b, Hadamard argument and single value product argument groups must have the same order.",
				exception.getMessage());
	}

	@Test
	@DisplayName("constructed with Hadamard argument from different group throws IllegalArgumentException")
	void constructWithDiffGroupHadamard() {
		final HadamardArgument otherGroupHadamardArgument = new ArgumentGenerator(otherGqGroup).genHadamardArgument(m, n);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ProductArgument(commitmentB, otherGroupHadamardArgument, singleValueProductArgument));
		assertEquals("The commitment b, Hadamard argument and single value product argument groups must have the same order.",
				exception.getMessage());
	}

	@Test
	@DisplayName("constructed with single value product argument from different group throws IllegalArgumentException")
	void constructWithDiffGroupSingleValueProduct() {
		final SingleValueProductArgument otherSingleValueProductArgument = new ArgumentGenerator(otherGqGroup).genSingleValueProductArgument(n);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ProductArgument(commitmentB, hadamardArgument, otherSingleValueProductArgument));
		assertEquals("The commitment b, Hadamard argument and single value product argument groups must have the same order.",
				exception.getMessage());
	}

	@Test
	@DisplayName("constructed with hadamard and single value product arguments with different n dimension throws IllegalArgumentException")
	void constructDiffNArguments() {
		final SingleValueProductArgument biggerNSingleValueProductArgument = argumentGenerator.genSingleValueProductArgument(n + 1);

		final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> new ProductArgument(commitmentB, hadamardArgument, biggerNSingleValueProductArgument));
		assertEquals("The Hadamard and single value product arguments must have the same dimension n.", exception.getMessage());
	}

}
