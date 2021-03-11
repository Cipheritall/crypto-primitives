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
package ch.post.it.evoting.cryptoprimitives.test.tools.math;

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.math.GroupElement;
import ch.post.it.evoting.cryptoprimitives.math.MathematicalGroup;

public class TestGroup implements MathematicalGroup<TestGroup> {
	@Override
	public boolean isGroupMember(BigInteger value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public GroupElement<TestGroup> getIdentity() {
		throw new UnsupportedOperationException();
	}

	@Override
	public BigInteger getQ() {
		throw new UnsupportedOperationException();
	}
}

