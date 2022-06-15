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
package ch.post.it.evoting.cryptoprimitives.internal.utils;

import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * Provides methods to perform operations on {@link GroupVector}s of {@link ZqElement}s.
 */
public class VectorUtils {

	private VectorUtils() {
		// Intentionally left blank.
	}

	/**
	 * Adds the first vector to the second one element-wise.
	 *
	 * @param first  the first vector.
	 * @param second the second vector.
	 * @return a new {@link GroupVector} which is the result of {@code first} + {@code second}.
	 */
	public static GroupVector<ZqElement, ZqGroup> vectorAddition(final GroupVector<ZqElement, ZqGroup> first,
			final GroupVector<ZqElement, ZqGroup> second) {
		checkNotNull(first);
		checkNotNull(second);
		checkArgument(first.size() == second.size(), "The vectors to be added must have the same size.");
		checkArgument(first.getGroup().equals(second.getGroup()), "Both vectors must have the same group.");

		final int l = first.size();

		return IntStream.range(0, l).mapToObj(i -> first.get(i).add(second.get(i))).collect(toGroupVector());
	}

	/**
	 * Multiplies a first vector of GqElements with a second vector of GqElements element-wise.
	 *
	 * @param first  the first vector.
	 * @param second the second vector.
	 * @return a new {@link GroupVector} which is the result of {@code first} * {@code second}.
	 */
	public static GroupVector<GqElement, GqGroup> vectorMultiplication(final GroupVector<GqElement, GqGroup> first,
			final GroupVector<GqElement, GqGroup> second) {
		checkNotNull(first);
		checkNotNull(second);
		checkArgument(first.size() == second.size(), "The vectors to be multiplied must have the same size.");
		checkArgument(first.getGroup().equals(second.getGroup()), "Both vectors must have the same group.");

		final int l = first.size();

		return IntStream.range(0, l).mapToObj(i -> first.get(i).multiply(second.get(i))).collect(toGroupVector());
	}

	/**
	 * Exponentiates a vector of GqElements by a ZqElement.
	 *
	 * @param vector   the vector to exponentiate.
	 * @param exponent the value to which to exponentiate the vector.
	 * @return a new {@link GroupVector} which is the result of vector<sup>exponent</sup>.
	 */
	public static GroupVector<GqElement, GqGroup> vectorExponentiation(final GroupVector<GqElement, GqGroup> vector, final ZqElement exponent) {
		checkNotNull(vector);
		checkNotNull(exponent);

		return vector.stream().map(element -> element.exponentiate(exponent)).collect(toGroupVector());
	}

	/**
	 * Multiplies a vector with a scalar.
	 *
	 * @param scalar the scalar to be multiplied with.
	 * @param vector the vector to be multiplied with.
	 * @return the vector resulting from the scalar product {@code scalar} * {@code vector}.
	 */
	public static GroupVector<ZqElement, ZqGroup> vectorScalarMultiplication(final ZqElement scalar, final GroupVector<ZqElement, ZqGroup> vector) {
		checkNotNull(vector);
		checkNotNull(scalar);
		checkArgument(vector.getGroup().equals(scalar.getGroup()), "The scalar must be of the same group than the vector.");

		return vector.stream().map(scalar::multiply).collect(toGroupVector());
	}

}
