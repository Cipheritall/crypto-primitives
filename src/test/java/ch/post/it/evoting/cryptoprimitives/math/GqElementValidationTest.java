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
package ch.post.it.evoting.cryptoprimitives.math;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;

class GqElementValidationTest {

	private static GqGroup group;

	private static BigInteger p;

	private static BigInteger elementValue;

	@BeforeAll
	public static void setUp() {
		group = GroupTestData.getLargeGqGroup();
		p = group.getP();
		elementValue = BigInteger.ONE;
	}

	public static Stream<Arguments> createGqElementFromGroupWithNulls() {
		return Stream.of(Arguments.of(null, group), Arguments.of(elementValue, null));
	}

	public static Stream<Arguments> createGqElementFromGroupWithInvalidValues() {
		return Stream.of(Arguments.of(BigInteger.ZERO, group), Arguments.of(p, group));
	}

	@ParameterizedTest
	@MethodSource("createGqElementFromGroupWithNulls")
	void testGqElementCreationWithNullThrows(BigInteger value, GqGroup group) {
		assertThrows(NullPointerException.class, () -> GqElement.create(value, group));
	}

	@ParameterizedTest
	@MethodSource("createGqElementFromGroupWithInvalidValues")
	void testGqElementCreationWithInvalidValuesThrows(BigInteger value, GqGroup group) {
		assertThrows(IllegalArgumentException.class, () -> GqElement.create(value, group));
	}
}
