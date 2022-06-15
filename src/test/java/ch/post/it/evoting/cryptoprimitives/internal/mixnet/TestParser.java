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
package ch.post.it.evoting.cryptoprimitives.internal.mixnet;

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;

public class TestParser {

	static GroupVector<GqElement, GqGroup> parseCommitment(final JsonData parent, final String commitmentField, final GqGroup group) {
		final BigInteger[] values = parent.get(commitmentField, BigInteger[].class);
		return Arrays.stream(values)
				.map(bi -> GqElementFactory.fromValue(bi, group))
				.collect(toGroupVector());
	}

	static GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> parseCiphertexts(final JsonData ciphertextsData, final GqGroup group) {
		final List<ElGamalMultiRecipientCiphertext> results = new LinkedList<>();
		for (final JsonNode ciphertextNode : ciphertextsData.getJsonNode()) {
			results.add(parseCiphertext(ciphertextNode, group));
		}
		return GroupVector.from(results);
	}

	static ElGamalMultiRecipientCiphertext parseCiphertext(final JsonNode ciphertextNode, final GqGroup group) {
		final JsonData ciphertextData = new JsonData(ciphertextNode);
		final BigInteger gamma = ciphertextData.get("gamma", BigInteger.class);
		final GqElement gammaElement = GqElementFactory.fromValue(gamma, group);
		final BigInteger[] phis = ciphertextData.get("phis", BigInteger[].class);
		final List<GqElement> phiElements = Arrays.stream(phis).map(value -> GqElementFactory.fromValue(value, group)).toList();
		return ElGamalMultiRecipientCiphertext.create(gammaElement, phiElements);
	}
}
