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

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Represents the statement for a single value product argument, consisting of a commitment and a product.
 */
class SingleValueProductStatement {

	private final GqElement commitment;
	private final ZqElement product;

	/**
	 * Instantiates a single value product statement object.
	 *
	 * <p>The commitment and product passed as arguments must both be non null and have the same group order.</p>
	 *
	 * @param commitment c<sub>a</sub>, a {@link GqElement}
	 * @param product    b, a {@link ZqElement}
	 */
	SingleValueProductStatement(final GqElement commitment, final ZqElement product) {
		checkNotNull(commitment);
		checkNotNull(product);
		checkArgument(commitment.getGroup().getQ().equals(product.getGroup().getQ()),
				"The group of the commitment and the group of the product must have the same order");
		this.commitment = commitment;
		this.product = product;
	}

	GqElement getCommitment() {
		return commitment;
	}

	ZqElement getProduct() {
		return product;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		SingleValueProductStatement that = (SingleValueProductStatement) o;
		return commitment.equals(that.commitment) &&
				product.equals(that.product);
	}

	@Override
	public int hashCode() {
		return Objects.hash(commitment, product);
	}
}
