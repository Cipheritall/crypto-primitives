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
package ch.post.it.evoting.cryptoprimitives.internal.zeroknowledgeproofs;

import static ch.post.it.evoting.cryptoprimitives.internal.math.Vectors.vectorAddition;
import static ch.post.it.evoting.cryptoprimitives.internal.math.Vectors.vectorExponentiation;
import static ch.post.it.evoting.cryptoprimitives.internal.math.Vectors.vectorMultiplication;
import static ch.post.it.evoting.cryptoprimitives.internal.math.Vectors.vectorScalarMultiplication;
import static ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.utils.Validations.allEqual;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.PlaintextEqualityProof;
import ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.ZeroKnowledgeProof;

@SuppressWarnings("java:S117")
public class PlaintextEqualityProofService {

	private static final String PLAINTEXT_EQUALITY_PROOF = "PlaintextEqualityProof";
	private final RandomService randomService;
	private final HashService hashService;

	public PlaintextEqualityProofService(final RandomService randomService, final HashService hashService) {
		this.randomService = checkNotNull(randomService);
		this.hashService = checkNotNull(hashService);
	}

	/**
	 * Computes the phi-function for plaintext equality.
	 *
	 * @param preImage        (x, x') ∈ Z<sub>q</sub><sup>2</sup>. Not null.
	 * @param firstPublicKey  h ∈ G<sub>q</sub>. Not null.
	 * @param secondPublicKey h' ∈ G<sub>q</sub>. Not null.
	 * @return an image (g<sup>x</sup>, g<sup>x'</sup>, h<sup>x</sup> / h'<sup>x'</sup>) ∈ G<sub>q</sub><sup>3</sup>
	 * @throws NullPointerException     if any of the parameters is null.
	 * @throws IllegalArgumentException if
	 *                                  <ul>
	 *                                      <li>the preImage is not of size 2</li>
	 *                                      <li>the public keys do not have the same group</li>
	 *                                      <li>the preImage does not have the same group order as the public keys</li>
	 *                                  </ul>
	 */
	static GroupVector<GqElement, GqGroup> computePhiPlaintextEquality(final GroupVector<ZqElement, ZqGroup> preImage, final GqElement firstPublicKey,
			final GqElement secondPublicKey) {

		checkNotNull(preImage);
		checkNotNull(firstPublicKey);
		checkNotNull(secondPublicKey);
		checkArgument(preImage.size() == 2, "The preImage must be of size 2.");

		// Cross group checking.
		checkArgument(firstPublicKey.getGroup().equals(secondPublicKey.getGroup()), "The two public keys must have the same group.");
		checkArgument(preImage.getGroup().hasSameOrderAs(firstPublicKey.getGroup()), "The preImage and public keys must have the same group order.");

		final GqElement g = firstPublicKey.getGroup().getGenerator();
		final ZqElement x = preImage.get(0);
		final ZqElement x_prime = preImage.get(1);
		final GqElement h = firstPublicKey;
		final GqElement h_prime = secondPublicKey;

		return GroupVector.of(g.exponentiate(x), g.exponentiate(x_prime), h.exponentiate(x).divide(h_prime.exponentiate(x_prime)));
	}

	/**
	 * @see ZeroKnowledgeProof#genPlaintextEqualityProof(ElGamalMultiRecipientCiphertext, ElGamalMultiRecipientCiphertext, GqElement, GqElement,
	 * GroupVector, List)
	 */
	public PlaintextEqualityProof genPlaintextEqualityProof(final ElGamalMultiRecipientCiphertext firstCiphertext,
			final ElGamalMultiRecipientCiphertext secondCiphertext, final GqElement firstPublicKey, final GqElement secondPublicKey,
			final GroupVector<ZqElement, ZqGroup> randomness, final List<String> auxiliaryInformation) {

		checkNotNull(firstCiphertext);
		checkNotNull(secondCiphertext);
		checkNotNull(firstPublicKey);
		checkNotNull(secondPublicKey);
		checkNotNull(randomness);
		checkNotNull(auxiliaryInformation);
		checkArgument(auxiliaryInformation.stream().allMatch(Objects::nonNull), "The auxiliary information must not contain null objects.");

		// Dimensions checking.
		checkArgument(firstCiphertext.size() == 1, "The first ciphertext must have exactly one phi.");
		checkArgument(secondCiphertext.size() == 1, "The second ciphertext must have exactly one phi.");

		checkArgument(randomness.size() == 2, "The randomness vector must have exactly two elements.");

		// Cross group checking.
		final List<GroupVectorElement<GqGroup>> gqGroups = Arrays.asList(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey);
		checkArgument(allEqual(gqGroups.stream(), GroupVectorElement::getGroup),
				"The ciphertexts and public keys must all belong to the same group.");
		checkArgument(firstCiphertext.getGroup().hasSameOrderAs(randomness.getGroup()),
				"The randomness and ciphertexts and public keys must have the same group order.");

		// Context.
		final GqGroup gqGroup = firstCiphertext.getGroup();
		final ZqGroup zqGroup = randomness.getGroup();
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();
		final GqElement g = gqGroup.getGenerator();

		// Variables.
		final GqElement h = firstPublicKey;
		final GqElement h_prime = secondPublicKey;
		final GqElement c_0 = firstCiphertext.getGamma();
		final GqElement c_1 = firstCiphertext.get(0);
		final GqElement c_0_prime = secondCiphertext.getGamma();
		final GqElement c_1_prime = secondCiphertext.get(0);
		final List<String> i_aux = List.copyOf(auxiliaryInformation);

		// Operation.
		final GroupVector<ZqElement, ZqGroup> b = randomService.genRandomVector(q, 2);
		final GroupVector<GqElement, GqGroup> c = computePhiPlaintextEquality(b, h, h_prime);
		final HashableList f = HashableList.of(HashableBigInteger.from(p), HashableBigInteger.from(q), g, h, h_prime);
		final GroupVector<GqElement, GqGroup> y = GroupVector.of(c_0, c_0_prime, c_1.divide(c_1_prime));

		final HashableList h_aux;
		if (!i_aux.isEmpty()) {
			h_aux = HashableList.of(HashableString.from(PLAINTEXT_EQUALITY_PROOF),
					c_1,
					c_1_prime,
					HashableList.from(i_aux.stream()
							.map(HashableString::from)
							.toList()));
		} else {
			h_aux = HashableList.of(HashableString.from(PLAINTEXT_EQUALITY_PROOF), c_1, c_1_prime);
		}

		final BigInteger eValue = byteArrayToInteger(hashService.recursiveHash(f, y, c, h_aux));
		final ZqElement e = ZqElement.create(eValue, zqGroup);
		final GroupVector<ZqElement, ZqGroup> z = vectorAddition(b, vectorScalarMultiplication(e, randomness));

		return new PlaintextEqualityProof(e, z);
	}

	/**
	 * @see ZeroKnowledgeProof#verifyPlaintextEquality(ElGamalMultiRecipientCiphertext, ElGamalMultiRecipientCiphertext, GqElement, GqElement,
	 * PlaintextEqualityProof, List)
	 */
	public boolean verifyPlaintextEquality(final ElGamalMultiRecipientCiphertext firstCiphertext,
			final ElGamalMultiRecipientCiphertext secondCiphertext, final GqElement firstPublicKey, final GqElement secondPublicKey,
			final PlaintextEqualityProof plaintextEqualityProof, final List<String> auxiliaryInformation) {

		checkNotNull(firstCiphertext);
		checkNotNull(secondCiphertext);
		checkNotNull(firstPublicKey);
		checkNotNull(secondPublicKey);
		checkNotNull(plaintextEqualityProof);
		checkNotNull(auxiliaryInformation);

		checkArgument(auxiliaryInformation.stream().allMatch(Objects::nonNull), "The auxiliary information must not contain null objects.");

		// Dimensions checking.
		checkArgument(firstCiphertext.size() == 1, "The first ciphertext must have exactly one phi.");
		checkArgument(secondCiphertext.size() == 1, "The second ciphertext must have exactly one phi.");

		// Cross group checking.
		final List<GroupVectorElement<GqGroup>> gqGroups = Arrays.asList(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey);
		checkArgument(allEqual(gqGroups.stream(), GroupVectorElement::getGroup),
				"The ciphertexts and public keys must all belong to the same group.");
		checkArgument(firstCiphertext.getGroup().hasSameOrderAs(plaintextEqualityProof.get_z().getGroup()),
				"The plaintext equality proof must have the same group order as the ciphertexts and the public keys.");

		// Context.
		final GqGroup gqGroup = firstCiphertext.getGroup();
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();
		final GqElement g = gqGroup.getGenerator();

		// Variables.
		final GqElement c_0 = firstCiphertext.getGamma();
		final GqElement c_1 = firstCiphertext.get(0);
		final GqElement c_0_prime = secondCiphertext.getGamma();
		final GqElement c_1_prime = secondCiphertext.get(0);
		final GqElement h = firstPublicKey;
		final GqElement h_prime = secondPublicKey;
		final PlaintextEqualityProof ez = plaintextEqualityProof;
		final List<String> i_aux = List.copyOf(auxiliaryInformation);
		final GroupVector<ZqElement, ZqGroup> z = ez.get_z();
		final ZqElement e = ez.get_e();

		// Operation.
		final GroupVector<GqElement, GqGroup> x = computePhiPlaintextEquality(z, h, h_prime);
		final HashableList f = HashableList.of(HashableBigInteger.from(p), HashableBigInteger.from(q), g, h, h_prime);
		final GroupVector<GqElement, GqGroup> y = GroupVector.of(c_0, c_0_prime, c_1.divide(c_1_prime));
		final GroupVector<GqElement, GqGroup> c_prime = vectorMultiplication(x, vectorExponentiation(y, e.negate()));

		final HashableList h_aux;
		if (!i_aux.isEmpty()) {
			h_aux = HashableList.of(HashableString.from(PLAINTEXT_EQUALITY_PROOF),
					c_1,
					c_1_prime,
					HashableList.from(i_aux.stream()
							.map(HashableString::from)
							.toList()));
		} else {
			h_aux = HashableList.of(HashableString.from(PLAINTEXT_EQUALITY_PROOF), c_1, c_1_prime);
		}

		final BigInteger e_prime_value = byteArrayToInteger(hashService.recursiveHash(f, y, c_prime, h_aux));

		final ZqElement e_prime = ZqElement.create(e_prime_value, ZqGroup.sameOrderAs(gqGroup));
		return e.equals(e_prime);
	}
}
