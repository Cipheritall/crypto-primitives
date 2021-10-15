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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Represents a statement used for the calculation of a product argument.
 *
 * <p>Instances of this class are immutable.</p>
 */
@SuppressWarnings({"java:S100", "java:S116", "java:S117"})
class ProductStatement {

	private final GroupVector<GqElement, GqGroup> c_A;
	private final ZqElement b;
	private final int m;
	private final GqGroup group;

	/**
	 * Instantiates a {@link ProductStatement} with the given commitments and product.
	 * <p>
	 * Both - the commitments and the product - must be non null and have the same order <i>q</i>.
	 *
	 * @param c_A <b><i>c</i></b><sub>A</sub>, a vector of {@link GqElement}s
	 * @param b     <i>b</i>, a {@link ZqElement}
	 */
	ProductStatement(final GroupVector<GqElement, GqGroup> c_A, final ZqElement b) {
		checkNotNull(c_A);
		checkNotNull(b);
		checkArgument(c_A.getGroup().hasSameOrderAs(b.getGroup()),
				"The commitments and the product must have the same order q.");

		this.c_A = c_A;
		this.b = b;
		this.m = c_A.size();
		this.group = c_A.getGroup();
	}

	GroupVector<GqElement, GqGroup> get_c_A() {
		return c_A;
	}

	ZqElement get_b() {
		return b;
	}

	int get_m() {
		return this.m;
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
		final ProductStatement that = (ProductStatement) o;
		return c_A.equals(that.c_A) && b.equals(that.b);
	}

	@Override
	public int hashCode() {
		return Objects.hash(c_A, b);
	}
}
