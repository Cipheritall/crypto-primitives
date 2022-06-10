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
package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

/**
 * A decryption proof (e, z) composed of a hash value e and a vector of proof elements z.
 */
public record DecryptionProof(ZqElement e, GroupVector<ZqElement, ZqGroup> z) implements GroupVectorElement<ZqGroup>, HashableList {

	public DecryptionProof {
		checkNotNull(e);
		checkNotNull(z);
		checkArgument(e.getGroup().equals(z.getGroup()), "e and z must have the same group.");
	}

	@Override
	public ZqGroup getGroup() {
		return e.getGroup();
	}

	@Override
	public int size() {
		return z.size();
	}

	@Override
	public List<Hashable> toHashableForm() {
		return List.of(e, z);
	}
}
