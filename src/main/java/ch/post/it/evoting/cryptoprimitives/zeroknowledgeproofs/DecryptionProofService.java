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
package ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs;

import static ch.post.it.evoting.cryptoprimitives.ConversionService.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.GroupVector.toGroupVector;
import static ch.post.it.evoting.cryptoprimitives.Validations.allEqual;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPrivateKey;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalService;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

public class DecryptionProofService {

	private final ElGamalService elGamalService = new ElGamalService();
	private final RandomService randomService;
	private final HashService hashService;

	DecryptionProofService(final RandomService randomService, final HashService hashService) {
		this.randomService = checkNotNull(randomService);
		this.hashService = checkNotNull(hashService);
	}

	/**
	 * Computes an image of a 𝜙-function for decryption given a preimage and a base γ.
	 * <p>
	 * The pre-image and the base must have the same group order q.
	 *
	 * @param preImage (x<sub>0</sub>, ..., x<sub>l-1</sub>) ∈ Z<sub>q</sub><sup>l</sup>. Not null.
	 * @param base     γ ∈ G<sub>q</sub>. Not null.
	 * @return an image (y<sub>0</sub>, ..., y<sub>2l-1</sub>).
	 */
	public static GroupVector<GqElement, GqGroup> computePhiDecryption(final GroupVector<ZqElement, ZqGroup> preImage, final GqElement base) {
		checkNotNull(preImage);
		checkNotNull(base);
		checkArgument(preImage.getGroup().hasSameOrderAs(base.getGroup()), "The preImage and base should have the same group order.");

		final GqElement g = base.getGroup().getGenerator();

		final GroupVector<GqElement, GqGroup> image = Stream.concat(
				preImage.stream().map(g::exponentiate),
				preImage.stream().map(base::exponentiate))
				.collect(toGroupVector());

		return GroupVector.from(image);
	}

	/**
	 * Generates a proof of validity for the provided decryption.
	 * <p>
	 * The input objects must comply with the following:
	 * <ul>
	 *     <li>the message must correspond to the ciphertext decrypted with the secret key</li>
	 *     <li>the ciphertext/message is at most as long as the secret key/public key</li>
	 *     <li>the ciphertext and the secret key must have the same group order</li>
	 * </ul>
	 *
	 * @param ciphertext           c, an ElGamal ciphertext for which correct decryption is to be proved. Must be non null.
	 * @param keyPair              (pk, sk), the pair of public key and secret key used for encryption and decryption. Must be non null.
	 * @param message              m, the message that is obtained by decrypting c with the secret key {@code sk}. Must be non null.
	 * @param auxiliaryInformation i<sub>aux</sub>, auxiliary information to be used for the hash. Must be non null. Can be empty.
	 * @return a decryption proof.
	 */
	public DecryptionProof genDecryptionProof(final ElGamalMultiRecipientCiphertext ciphertext, final ElGamalMultiRecipientKeyPair keyPair,
			final ElGamalMultiRecipientMessage message, final List<String> auxiliaryInformation) {
		@SuppressWarnings("squid:S00117")
		final ElGamalMultiRecipientCiphertext C = checkNotNull(ciphertext);
		checkNotNull(keyPair);
		final ElGamalMultiRecipientPrivateKey sk = keyPair.getPrivateKey();
		final ElGamalMultiRecipientPublicKey pk = keyPair.getPublicKey();
		final ElGamalMultiRecipientMessage m = checkNotNull(message);
		checkNotNull(auxiliaryInformation);
		ImmutableList<Hashable> iAux = auxiliaryInformation.stream().map(HashableString::from).collect(ImmutableList.toImmutableList());

		// Context.
		final GqGroup gqGroup = ciphertext.getGroup();
		final GqElement g = gqGroup.getGenerator();
		checkArgument(hashService.getHashLength() * Byte.SIZE < gqGroup.getQ().bitLength(),
				"The hash service's bit length must be smaller than the bit length of q.");

		// Cross-checks.
		checkArgument(C.size() <= sk.size(), "The ciphertext length cannot be greater than the secret key length.");
		checkArgument(C.getGroup().hasSameOrderAs(sk.getGroup()), "The ciphertext and the secret key group must have the same order.");
		checkArgument(m.equals(elGamalService.getMessage(C, sk)), "The message must be equal to the decrypted ciphertext.");

		// Helper variables.
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();
		final int l = ciphertext.size();
		final GqElement gamma = C.getGamma();

		// Algorithm.
		final GroupVector<ZqElement, ZqGroup> b = randomService.genRandomVector(q, l);
		final GroupVector<GqElement, GqGroup> c = computePhiDecryption(b, gamma);
		final ImmutableList<Hashable> f = ImmutableList.of(HashableBigInteger.from(p), HashableBigInteger.from(q), g, gamma);
		final ElGamalMultiRecipientPublicKey pkPrime = pk.compress(l);
		final GroupVector<GqElement, GqGroup> phis = C.getPhis();
		final GroupVector<GqElement, GqGroup> y = Stream.concat(
				pkPrime.stream(),
				IntStream.range(0, l).mapToObj(i -> phis.get(i).multiply(m.get(i).inverse())))
				.collect(toGroupVector());
		final HashableList hAux = getHashElementList("DecryptionProof", phis, m, iAux);
		final BigInteger eValue = byteArrayToInteger(hashService.recursiveHash(HashableList.from(f), y, c, hAux));
		final ZqElement e = ZqElement.create(eValue, ZqGroup.sameOrderAs(gqGroup));
		final ElGamalMultiRecipientPrivateKey skPrime = sk.compress(l);
		final GroupVector<ZqElement, ZqGroup> z = vectorAddition(b, vectorScalarMultiplication(skPrime.stream().collect(toGroupVector()), e));

		return new DecryptionProof(e, z);
	}

	/**
	 * Verifies the validity of a given {@link DecryptionProof}.
	 * <p>
	 * The input objects must comply with the following:
	 * <ul>
	 *     <li>The ciphertext, the message and the public key must have the same group.</li>
	 *     <li>The decryption proof must have the same group order as the ciphertext, the message and the public key.</li>
	 *     <li>The ciphertext, the message and the decryption proof's z must have the same size.</li>
	 *     <li>The ciphertext must be smaller than or equal to the public key.</li>
	 * </ul>
	 *
	 * @param ciphertext           C, the ciphertext that was used to generate the proof. Must be non null.
	 * @param publicKey            pk, the public key that was used to generate the proof. Must be non null.
	 * @param message              m, the message that was used to generate the proof. Must be non null.
	 * @param decryptionProof      (e, z), the decryption proof to be verified. Must be non null.
	 * @param auxiliaryInformation i<sub>aux</sub>, auxiliary information that was used during proof generation. Must be non null.
	 * @return {@code true} if the decryption proof is valid, {@code false} otherwise.
	 */
	public boolean verifyDecryption(final ElGamalMultiRecipientCiphertext ciphertext, final ElGamalMultiRecipientPublicKey publicKey,
			final ElGamalMultiRecipientMessage message, final DecryptionProof decryptionProof, final List<String> auxiliaryInformation) {
		final ElGamalMultiRecipientCiphertext C = checkNotNull(ciphertext);
		final ElGamalMultiRecipientPublicKey pk = checkNotNull(publicKey);
		final ElGamalMultiRecipientMessage m = checkNotNull(message);
		final DecryptionProof ez = checkNotNull(decryptionProof);
		checkNotNull(auxiliaryInformation);
		final ImmutableList<Hashable> iAux = auxiliaryInformation.stream().map(HashableString::from).collect(ImmutableList.toImmutableList());

		// Cross-checks
		checkArgument(allEqual(Stream.of((GroupVectorElement<GqGroup>) C, pk, m), GroupVectorElement::getGroup),
				"The ciphertext, the public key and the message must have the same group.");
		checkArgument(C.getGroup().hasSameOrderAs(ez.getGroup()),
				"The decryption proof must have the same group order as the ciphertext, the message and the public key.");
		checkArgument(allEqual(Stream.of((GroupVectorElement<GqGroup>) C, m, ez), GroupVectorElement::size),
				"The ciphertext, the message and the decryption proof must have the same size.");
		checkArgument(C.size() <= pk.size(), "The ciphertext, the message and the decryption proof must be smaller than or equal to the public key.");

		final GqGroup gqGroup = C.getGroup();
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();
		final GqElement g = gqGroup.getGenerator();
		final ZqElement e = ez.getE();
		final GroupVector<ZqElement, ZqGroup> z = ez.getZ();
		final GqElement gamma = C.getGamma();
		final GroupVector<GqElement, GqGroup> phis = C.getPhis();
		final int l = C.size();

		// Algorithm.
		final GroupVector<GqElement, GqGroup> x = computePhiDecryption(z, gamma);
		final ImmutableList<Hashable> f = ImmutableList.of(HashableBigInteger.from(p), HashableBigInteger.from(q), g, gamma);
		final ElGamalMultiRecipientPublicKey pkPrime = pk.compress(l);
		final GroupVector<GqElement, GqGroup> y = Stream.concat(
				pkPrime.stream(),
				IntStream.range(0, l).mapToObj(i -> phis.get(i).multiply(m.get(i).inverse())))
				.collect(toGroupVector());
		final GroupVector<GqElement, GqGroup> cPrime = IntStream.range(0, 2 * l)
				.mapToObj(i -> x.get(i).multiply(y.get(i).exponentiate(e.negate())))
				.collect(toGroupVector());
		final HashableList hAux = getHashElementList("DecryptionProof", phis, m, iAux);
		final byte[] h = hashService.recursiveHash(HashableList.from(f), y, cPrime, hAux);
		final BigInteger ePrime = byteArrayToInteger(h);

		return (e.getValue().equals(ePrime));
	}

	/**
	 * Adds the first vector to the second one element wise.
	 *
	 * @param first  the first vector
	 * @param second the second vector
	 * @return a new {@link GroupVector} which is the result of {@code first} + {@code second}
	 */
	private static GroupVector<ZqElement, ZqGroup> vectorAddition(final GroupVector<ZqElement, ZqGroup> first,
			GroupVector<ZqElement, ZqGroup> second) {
		checkNotNull(first);
		checkNotNull(second);
		checkArgument(first.size() == second.size(), "The vectors to be added must have the same size.");
		checkArgument(first.getGroup().equals(second.getGroup()), "Both vectors must have the same group.");

		final int l = first.size();

		return IntStream.range(0, l).mapToObj(i -> first.get(i).add(second.get(i))).collect(toGroupVector());
	}

	/**
	 * Multiplies a vector with a scalar.
	 *
	 * @param vector the vector to be multiplied with
	 * @param scalar the scalar to be multiplied with
	 * @return the vector resulting from the scalar product {@code scalar} * {@code product}
	 */
	private static GroupVector<ZqElement, ZqGroup> vectorScalarMultiplication(GroupVector<ZqElement, ZqGroup> vector, ZqElement scalar) {
		checkNotNull(vector);
		checkNotNull(scalar);
		checkArgument(vector.getGroup().equals(scalar.getGroup()), "The scalar must be of the same group than the vector.");

		return vector.stream().map(scalar::multiply).collect(toGroupVector());
	}

	private HashableList getHashElementList(final String id, final GroupVector<GqElement, GqGroup> phis,
			final ElGamalMultiRecipientMessage m,
			final ImmutableList<Hashable> iAux) {
		final ArrayList<Hashable> hAuxElements = new ArrayList<>();
		hAuxElements.add(HashableString.from(id));
		hAuxElements.add(phis);
		hAuxElements.add(m);
		if (!iAux.isEmpty()) {
			hAuxElements.add(HashableList.from(iAux));
		}
		return HashableList.from(hAuxElements);
	}
}