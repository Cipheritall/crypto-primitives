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

package ch.post.it.evoting.cryptoprimitives.internal.elgamal;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.stream.Collectors;
import java.util.stream.IntStream;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamal;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;

public class ElGamalMultiRecipientPublicKeys {

	private ElGamalMultiRecipientPublicKeys() {
		//Intentionally left blank
	}

	/**
	 * @see	ElGamal#combinePublicKeys(GroupVector)
	 */
	public static ElGamalMultiRecipientPublicKey combinePublicKeys(final GroupVector<ElGamalMultiRecipientPublicKey, GqGroup> publicKeyList) {
		checkNotNull(publicKeyList);

		final GroupVector<ElGamalMultiRecipientPublicKey, GqGroup> pk = publicKeyList;
		final int N = publicKeyList.getElementSize();
		final int s = publicKeyList.size();
		final GqGroup group = publicKeyList.getGroup();

		return IntStream.range(0, N)
				.mapToObj(i -> IntStream.range(0, s)
						.mapToObj(j -> pk.get(j).get(i))
						.reduce(group.getIdentity(), GqElement::multiply))
				.collect(Collectors.collectingAndThen(Collectors.toList(), ElGamalMultiRecipientPublicKey::new));
	}
}
