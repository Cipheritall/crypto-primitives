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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Represents the statement for a single value product argument, consisting of a commitment and a product.
 *
 * <p>Instances of this class are immutable.</p>
 */
@SuppressWarnings({ "java:S100", "java:S116", "java:S117" })
public
class SingleValueProductStatement {

	private final GqElement c_a;
	private final ZqElement b;

	private final GqGroup group;

	/**
	 * Instantiates a single value product statement object.
	 *
	 * <p>The commitment and product passed as arguments must both be non null and have the same group order.</p>
	 *
	 * @param c_a c<sub>a</sub>, a {@link GqElement}
	 * @param b   b, a {@link ZqElement}
	 */
	public SingleValueProductStatement(final GqElement c_a, final ZqElement b) {
		checkNotNull(c_a);
		checkNotNull(b);
		checkArgument(c_a.getGroup().hasSameOrderAs(b.getGroup()),
				"The group of the commitment and the group of the product must have the same order");
		this.c_a = c_a;
		this.b = b;
		this.group = c_a.getGroup();
	}

	public GqElement get_c_a() {
		return c_a;
	}

	public ZqElement get_b() {
		return b;
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
		final SingleValueProductStatement that = (SingleValueProductStatement) o;
		return c_a.equals(that.c_a) &&
				b.equals(that.b);
	}

	@Override
	public int hashCode() {
		return Objects.hash(c_a, b);
	}
}
