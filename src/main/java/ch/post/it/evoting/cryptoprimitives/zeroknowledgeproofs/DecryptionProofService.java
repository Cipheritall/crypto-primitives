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

import static ch.post.it.evoting.cryptoprimitives.math.GroupVector.toGroupVector;
import static ch.post.it.evoting.cryptoprimitives.utils.ConversionService.byteArrayToInteger;
import static ch.post.it.evoting.cryptoprimitives.utils.Validations.allEqual;
import static ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.VectorUtils.vectorAddition;
import static ch.post.it.evoting.cryptoprimitives.zeroknowledgeproofs.VectorUtils.vectorScalarMultiplication;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPrivateKey;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalService;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableString;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GroupVectorElement;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.utils.Verifiable;

/**
 * <p>This class is thread safe.</p>
 */
@SuppressWarnings("java:S117")
public class DecryptionProofService {

	private static final String DECRYPTION_PROOF = "DecryptionProof";

	private final ElGamalService elGamalService = new ElGamalService();
	private final RandomService randomService;
	private final HashService hashService;

	DecryptionProofService(final RandomService randomService, final HashService hashService) {
		this.randomService = checkNotNull(randomService);
		this.hashService = checkNotNull(hashService);
	}

	/**
	 * Computes an image of a phi-function for decryption given a preimage and a base γ.
	 * <p>
	 * The pre-image and the base must have the same group order q.
	 *
	 * @param preImage (x<sub>0</sub>, ..., x<sub>l-1</sub>) ∈ Z<sub>q</sub><sup>l</sup>. Not null.
	 * @param base     γ ∈ G<sub>q</sub>. Not null.
	 * @return an image (y<sub>0</sub>, ..., y<sub>2l-1</sub>).
	 */
	static GroupVector<GqElement, GqGroup> computePhiDecryption(final GroupVector<ZqElement, ZqGroup> preImage, final GqElement base) {
		checkNotNull(preImage);
		checkNotNull(base);
		checkArgument(preImage.getGroup().hasSameOrderAs(base.getGroup()), "The preImage and base should have the same group order.");

		final GroupVector<ZqElement, ZqGroup> x = preImage;
		final GqElement gamma = base;

		final GqElement g = base.getGroup().getGenerator();

		final GroupVector<GqElement, GqGroup> y = Stream.concat(
						x.stream().map(g::exponentiate),
						x.stream().map(gamma::exponentiate))
				.collect(toGroupVector());

		return GroupVector.from(y);
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
	DecryptionProof genDecryptionProof(final ElGamalMultiRecipientCiphertext ciphertext, final ElGamalMultiRecipientKeyPair keyPair,
			final ElGamalMultiRecipientMessage message, final List<String> auxiliaryInformation) {
		checkNotNull(ciphertext);
		checkNotNull(keyPair);
		checkNotNull(message);
		checkNotNull(auxiliaryInformation);

		checkArgument(auxiliaryInformation.stream().allMatch(Objects::nonNull), "The auxiliary information must not contain null elements.");

		final List<String> i_aux = List.copyOf(auxiliaryInformation);
		final ElGamalMultiRecipientCiphertext C = ciphertext;
		final ElGamalMultiRecipientPrivateKey sk = keyPair.getPrivateKey();
		final ElGamalMultiRecipientPublicKey pk = keyPair.getPublicKey();
		final ElGamalMultiRecipientMessage m = message;

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
		final HashableList f = HashableList.of(HashableBigInteger.from(p), HashableBigInteger.from(q), g, gamma);

		final GroupVector<GqElement, GqGroup> phi = C.getPhi();
		final GroupVector<GqElement, GqGroup> y = Stream.concat(
						pk.stream().limit(l),
						IntStream.range(0, l).mapToObj(i -> phi.get(i).multiply(m.get(i).invert())))
				.collect(toGroupVector());
		final HashableList h_aux;
		if (!i_aux.isEmpty()) {
			h_aux = HashableList.of(HashableString.from(DECRYPTION_PROOF),
					phi,
					m,
					HashableList.from(i_aux.stream()
							.map(HashableString::from)
							.toList()));
		} else {
			h_aux = HashableList.of(HashableString.from(DECRYPTION_PROOF), phi, m);
		}
		final BigInteger e_value = byteArrayToInteger(hashService.recursiveHash(f, y, c, h_aux));
		final ZqElement e = ZqElement.create(e_value, ZqGroup.sameOrderAs(gqGroup));
		final GroupVector<ZqElement, ZqGroup> sk_prime = sk.stream().limit(l).collect(toGroupVector());
		final GroupVector<ZqElement, ZqGroup> z = vectorAddition(b, vectorScalarMultiplication(e, sk_prime));

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
	Verifiable verifyDecryption(final ElGamalMultiRecipientCiphertext ciphertext, final ElGamalMultiRecipientPublicKey publicKey,
			final ElGamalMultiRecipientMessage message, final DecryptionProof decryptionProof, final List<String> auxiliaryInformation) {
		checkNotNull(ciphertext);
		checkNotNull(publicKey);
		checkNotNull(message);
		checkNotNull(decryptionProof);
		checkNotNull(auxiliaryInformation);
		checkArgument(auxiliaryInformation.stream().allMatch(Objects::nonNull), "The auxiliary information must not contain null elements.");

		final List<String> i_aux = List.copyOf(auxiliaryInformation);
		final ElGamalMultiRecipientCiphertext C = ciphertext;
		final ElGamalMultiRecipientPublicKey pk = publicKey;
		final ElGamalMultiRecipientMessage m = message;
		final DecryptionProof ez = decryptionProof;

		final GqGroup gqGroup = C.getGroup();
		final ZqGroup zqGroup = ez.getGroup();
		final BigInteger p = gqGroup.getP();
		final BigInteger q = gqGroup.getQ();

		final GqElement g = gqGroup.getGenerator();
		final ZqElement e = ez.getE();
		final GroupVector<ZqElement, ZqGroup> z = ez.getZ();
		final GqElement gamma = C.getGamma();
		final GroupVector<GqElement, GqGroup> phi = C.getPhi();
		final int l = C.size();

		checkArgument(hashService.getHashLength() * Byte.SIZE < q.bitLength(),
				"The hash service's bit length must be smaller than the bit length of q.");

		// Cross-checks
		checkArgument(allEqual(Stream.of((GroupVectorElement<GqGroup>) C, pk, m), GroupVectorElement::getGroup),
				"The ciphertext, the public key and the message must have the same group.");
		checkArgument(C.getGroup().hasSameOrderAs(ez.getGroup()),
				"The decryption proof must have the same group order as the ciphertext, the message and the public key.");
		checkArgument(allEqual(Stream.of((GroupVectorElement<GqGroup>) C, m, ez), GroupVectorElement::size),
				"The ciphertext, the message and the decryption proof must have the same size.");
		checkArgument(C.size() <= pk.size(), "The ciphertext, the message and the decryption proof must be smaller than or equal to the public key.");

		// Algorithm.
		final GroupVector<GqElement, GqGroup> x = computePhiDecryption(z, gamma);
		final HashableList f = HashableList.of(HashableBigInteger.from(p), HashableBigInteger.from(q), g, gamma);
		final GroupVector<GqElement, GqGroup> y = Stream.concat(
						pk.stream().limit(l),
						IntStream.range(0, l).mapToObj(i -> phi.get(i).multiply(m.get(i).invert())))
				.collect(toGroupVector());
		final GroupVector<GqElement, GqGroup> c_prime = IntStream.range(0, 2 * l)
				.mapToObj(i -> x.get(i).multiply(y.get(i).exponentiate(e.negate())))
				.collect(toGroupVector());
		final HashableList h_aux;
		if (!i_aux.isEmpty()) {
			h_aux = HashableList.of(HashableString.from(DECRYPTION_PROOF),
					phi,
					m,
					HashableList.from(i_aux.stream()
							.map(HashableString::from)
							.toList()));
		} else {
			h_aux = HashableList.of(HashableString.from(DECRYPTION_PROOF), phi, m);
		}
		final byte[] h = hashService.recursiveHash(f, y, c_prime, h_aux);
		final BigInteger e_prime_value = byteArrayToInteger(h);
		final ZqElement e_prime = ZqElement.create(e_prime_value, zqGroup);

		return Verifiable.create(() -> e.equals(e_prime), String.format("Could not verify decryption proof of ciphertext %s.", ciphertext));
	}

}
