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
package ch.post.it.evoting.cryptoprimitives.test.tools;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.test.tools.math.TestGroup;

public class TestSizedElement implements GroupVectorElement<TestGroup>, HashableList {

	private final int size;
	private final TestGroup group;

	public TestSizedElement(TestGroup group, int size) {
		this.group = group;
		this.size = size;
	}

	@Override
	public TestGroup getGroup() {
		return group;
	}

	@Override
	public int size() {
		return size;
	}

	@Override
	public ImmutableList<? extends Hashable> toHashableForm() {
		throw new UnsupportedOperationException();
	}
}
