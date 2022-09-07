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

import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPrivateKey;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;

public class ElGamalMultiRecipientKeyPairs {

	private ElGamalMultiRecipientKeyPairs() {
		//Intentionally left blank
	}

	/**
	 * Derives the public key from the private key with the given {@code generator}.
	 *
	 * @param elGamalMultiRecipientPrivateKey the private key from which to derive the public key
	 * @param generator the group generator to be used for the public key derivation. Must be non-null and must belong to a group of the same order as
	 *                  the private key group.
	 * @return the derived public key with the given {@code generator}.
	 */
	public static ElGamalMultiRecipientPublicKey derivePublicKey(ElGamalMultiRecipientPrivateKey elGamalMultiRecipientPrivateKey,
			final GqElement generator) {
		checkNotNull(generator);
		checkArgument(generator.getGroup().hasSameOrderAs(elGamalMultiRecipientPrivateKey.getGroup()),
				"The private key and the generator must belong to groups of the same order.");

		final GroupVector<GqElement, GqGroup> publicKeyElements = elGamalMultiRecipientPrivateKey.stream().parallel().map(generator::exponentiate).collect(toGroupVector());

		return new ElGamalMultiRecipientPublicKey(publicKeyElements);
	}
}
