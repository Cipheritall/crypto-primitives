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

import static ch.post.it.evoting.cryptoprimitives.Validations.allEqual;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

public class ProductArgument implements HashableList {

	private final SingleValueProductArgument singleValueProductArgument;
	private GqElement commitmentB;
	private HadamardArgument hadamardArgument;

	private final int m;
	private final int n;
	private final GqGroup group;

	/**
	 * Constructs a {@link ProductArgument}.
	 * <p>
	 * The {@code commitmentB}, {@code hadamardArgument} and {@code singleValueProductArgument} must comply with the following:
	 * <ul>
	 *     <li>belong to the same group</li>
	 *     <li>{@code hadamardArgument} and {@code singleValueProductArgument} must have the same dimension {@code n}</li>
	 * </ul>
	 *
	 * @param commitmentB                the commitment to a vector b. Non-null.
	 * @param hadamardArgument           the Hadamard argument. Non-null.
	 * @param singleValueProductArgument the Single Value Product argument. Non-null.
	 */
	public ProductArgument(final GqElement commitmentB, final HadamardArgument hadamardArgument,
			final SingleValueProductArgument singleValueProductArgument) {

		// Null checking.
		checkNotNull(commitmentB);
		checkNotNull(hadamardArgument);
		checkNotNull(singleValueProductArgument);

		// Cross group checking.
		final List<GqGroup> gqGroups = Arrays.asList(commitmentB.getGroup(), hadamardArgument.getGroup(), singleValueProductArgument.getGroup());
		checkArgument(allEqual(gqGroups.stream(), g -> g),
				"The commitment b, Hadamard argument and single value product argument groups must have the same order.");

		// Cross dimension checking.
		checkArgument(hadamardArgument.getN() == singleValueProductArgument.getN(),
				"The Hadamard and single value product arguments must have the same dimension n.");

		this.commitmentB = commitmentB;
		this.hadamardArgument = hadamardArgument;
		this.singleValueProductArgument = singleValueProductArgument;
		this.m = hadamardArgument.getM();
		this.n = hadamardArgument.getN();
		this.group = commitmentB.getGroup();
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
		this.n = singleValueProductArgument.getN();
		this.group = singleValueProductArgument.getGroup();
	}

	GqElement getCommitmentB() {
		return commitmentB;
	}

	HadamardArgument getHadamardArgument() {
		return hadamardArgument;
	}

	SingleValueProductArgument getSingleValueProductArgument() {
		return singleValueProductArgument;
	}

	int getM() {
		return m;
	}

	int getN() {
		return n;
	}

	GqGroup getGroup() {
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
		return Objects.equals(commitmentB, that.commitmentB) && Objects.equals(hadamardArgument, that.hadamardArgument)
				&& singleValueProductArgument.equals(that.singleValueProductArgument);
	}

	@Override
	public int hashCode() {
		return Objects.hash(commitmentB, hadamardArgument, singleValueProductArgument);
	}

	@Override
	public ImmutableList<? extends Hashable> toHashableForm() {
		if(commitmentB == null) {
			return ImmutableList.of(singleValueProductArgument);
		}
		return ImmutableList.of(commitmentB, hadamardArgument, singleValueProductArgument);
	}
}
