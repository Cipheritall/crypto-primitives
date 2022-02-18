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
package ch.post.it.evoting.cryptoprimitives.math;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Group of integers modulo q.
 *
 * <p> Instances of this class are immutable.</p>
 */
public class ZqGroup implements MathematicalGroup<ZqGroup> {
	private final BigInteger q;
	private final ZqElement identity;

	public ZqGroup(final BigInteger q) {
		checkNotNull(q);
		checkArgument(q.compareTo(BigInteger.valueOf(2)) >= 0);

		this.q = q;
		this.identity = ZqElement.create(BigInteger.ZERO, this);
	}

	/**
	 * Creates a ZqGroup with the same order as the given {@link GqGroup};
	 */
	public static ZqGroup sameOrderAs(final GqGroup gqGroup) {
		checkNotNull(gqGroup);
		return new ZqGroup(gqGroup.getQ());
	}

	@Override
	public boolean isGroupMember(final BigInteger value) {
		return value != null && value.compareTo(BigInteger.ZERO) >= 0 && value.compareTo(this.q) < 0;
	}

	@Override
	public ZqElement getIdentity() {
		return this.identity;
	}

	@Override
	public BigInteger getQ() {
		return this.q;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ZqGroup zqGroup = (ZqGroup) o;
		return q.equals(zqGroup.q);
	}

	@Override
	public int hashCode() {
		return Objects.hash(q);
	}

	@Override
	public String toString() {
		return "ZqGroup{" + "q=" + q + '}';
	}
}
