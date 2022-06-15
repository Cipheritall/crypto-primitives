/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.utils.Validations.allEqual;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

/**
 * <p>Instances of this class are immutable.</p>
 */
@SuppressWarnings({ "java:S100", "java:S116", "java:S117" })
public class ProductArgument implements HashableList {

	private final SingleValueProductArgument singleValueProductArgument;
	private final int m;
	private final int n;
	private final GqGroup group;
	private final GqElement c_b;
	private final HadamardArgument hadamardArgument;

	/**
	 * Constructs a {@link ProductArgument}.
	 * <p>
	 * The {@code commitmentB}, {@code hadamardArgument} and {@code singleValueProductArgument} must comply with the following:
	 * <ul>
	 *     <li>belong to the same group</li>
	 *     <li>{@code hadamardArgument} and {@code singleValueProductArgument} must have the same dimension {@code n}</li>
	 * </ul>
	 *
	 * @param c_b                        the commitment to a vector b. Non-null.
	 * @param hadamardArgument           the Hadamard argument. Non-null.
	 * @param singleValueProductArgument the Single Value Product argument. Non-null.
	 */
	public ProductArgument(final GqElement c_b, final HadamardArgument hadamardArgument,
			final SingleValueProductArgument singleValueProductArgument) {

		// Null checking.
		checkNotNull(c_b);
		checkNotNull(hadamardArgument);
		checkNotNull(singleValueProductArgument);

		// Cross group checking.
		final List<GqGroup> gqGroups = Arrays.asList(c_b.getGroup(), hadamardArgument.getGroup(), singleValueProductArgument.getGroup());
		checkArgument(allEqual(gqGroups.stream(), g -> g),
				"The commitment b, Hadamard argument and single value product argument groups must have the same order.");

		// Cross dimension checking.
		checkArgument(hadamardArgument.get_n() == singleValueProductArgument.get_n(),
				"The Hadamard and single value product arguments must have the same dimension n.");

		this.c_b = c_b;
		this.hadamardArgument = hadamardArgument;
		this.singleValueProductArgument = singleValueProductArgument;
		this.m = hadamardArgument.get_m();
		this.n = hadamardArgument.get_n();
		this.group = c_b.getGroup();
	}

	/**
	 * Constructs a {@link ProductArgument} with only a {@code singleValueProductArgument}. The commitment b and Hadamard argument remains null when
	 * using this constructor.
	 *
	 * @param singleValueProductArgument the Single Value Product Argument. Non-null.
	 */
	public ProductArgument(final SingleValueProductArgument singleValueProductArgument) {
		this.singleValueProductArgument = checkNotNull(singleValueProductArgument);
		this.m = 1;
		this.n = singleValueProductArgument.get_n();
		this.group = singleValueProductArgument.getGroup();
		this.c_b = null;
		this.hadamardArgument = null;
	}

	public Optional<GqElement> get_c_b() {
		return Optional.ofNullable(c_b);
	}

	public Optional<HadamardArgument> getHadamardArgument() {
		return Optional.ofNullable(hadamardArgument);
	}

	public SingleValueProductArgument getSingleValueProductArgument() {
		return singleValueProductArgument;
	}

	public int get_m() {
		return m;
	}

	public int get_n() {
		return n;
	}

	public GqGroup getGroup() {
		return group;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ProductArgument that = (ProductArgument) o;
		return Objects.equals(c_b, that.c_b) && Objects.equals(hadamardArgument, that.hadamardArgument)
				&& singleValueProductArgument.equals(that.singleValueProductArgument);
	}

	@Override
	public int hashCode() {
		return Objects.hash(c_b, hadamardArgument, singleValueProductArgument);
	}

	@Override
	public List<? extends Hashable> toHashableForm() {
		if (c_b == null) {
			return List.of(singleValueProductArgument);
		}
		return List.of(c_b, hadamardArgument, singleValueProductArgument);
	}
}
