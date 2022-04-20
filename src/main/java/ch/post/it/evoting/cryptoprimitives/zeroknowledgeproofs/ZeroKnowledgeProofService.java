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
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;
import java.util.stream.IntStream;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPrivateKey;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.utils.Verifiable;
import ch.post.it.evoting.cryptoprimitives.utils.VerificationResult;

/**
 * <p>This class is thread safe.</p>
 */
@SuppressWarnings("squid:S00117")
public class ZeroKnowledgeProofService implements ZeroKnowledgeProof {

	private final DecryptionProofService decryptionProofService;
	private final ExponentiationProofService exponentiationProofService;
	private final PlaintextEqualityProofService plaintextEqualityProofService;
	private final SchnorrProofService schnorrProofService;

	/**
	 * Instantiates a zero knowledge proof service which operates in a given group.
	 */
	public ZeroKnowledgeProofService() {
		final RandomService randomService = new RandomService();
		final HashService hashService = HashService.getInstance();

		decryptionProofService = new DecryptionProofService(randomService, hashService);
		exponentiationProofService = new ExponentiationProofService(randomService, hashService);
		plaintextEqualityProofService = new PlaintextEqualityProofService(randomService, hashService);
		schnorrProofService = new SchnorrProofService(randomService, hashService);
	}

	@VisibleForTesting
	public ZeroKnowledgeProofService(final RandomService randomService, final HashService hashService) {
		decryptionProofService = new DecryptionProofService(randomService, hashService);
		exponentiationProofService = new ExponentiationProofService(randomService, hashService);
		plaintextEqualityProofService = new PlaintextEqualityProofService(randomService, hashService);
		schnorrProofService = new SchnorrProofService(randomService, hashService);
	}

	@Override
	public VerifiableDecryptions genVerifiableDecryptions(final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts,
			final ElGamalMultiRecipientKeyPair keyPair, final List<String> auxiliaryInformation) {
		checkNotNull(ciphertexts);
		checkNotNull(keyPair);
		checkNotNull(auxiliaryInformation);

		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C = ciphertexts;
		final ElGamalMultiRecipientPrivateKey sk = keyPair.getPrivateKey();
		final List<String> i_aux = auxiliaryInformation;
		final int l = C.getElementSize();
		final int k = sk.size();

		// Cross-checks
		checkArgument(!C.isEmpty(), "There must be at least one ciphertext.");
		checkArgument(l <= k, "The ciphertexts must be at most as long as the keys in the key pair.");
		checkArgument(C.getGroup().equals(keyPair.getGroup()), "The ciphertexts and the key pair must have the same group.");

		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C_prime = C.stream()
				.map(c_i -> c_i.getPartialDecryption(sk))
				.collect(toGroupVector());
		final GroupVector<DecryptionProof, ZqGroup> pi_dec = IntStream.range(0, C.size())
				.mapToObj(i -> {
					final ElGamalMultiRecipientCiphertext c_i = C.get(i);
					final ElGamalMultiRecipientMessage phi_prime = new ElGamalMultiRecipientMessage(C_prime.get(i).getPhi());
					return decryptionProofService.genDecryptionProof(c_i, keyPair, phi_prime, i_aux);
				})
				.collect(toGroupVector());

		return new VerifiableDecryptions(C_prime, pi_dec);
	}

	@Override
	public VerificationResult verifyDecryptions(final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> ciphertexts,
			final ElGamalMultiRecipientPublicKey publicKey, final VerifiableDecryptions verifiableDecryptions,
			final List<String> auxiliaryInformation) {
		checkNotNull(ciphertexts);
		checkNotNull(publicKey);
		checkNotNull(verifiableDecryptions);
		checkNotNull(auxiliaryInformation);

		checkArgument(auxiliaryInformation.stream().allMatch(Objects::nonNull), "Auxiliary information cannot contain null elements.");

		final ImmutableList<String> i_aux = ImmutableList.copyOf(auxiliaryInformation);
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C = ciphertexts;
		final ElGamalMultiRecipientPublicKey pk = publicKey;
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C_prime = verifiableDecryptions.getCiphertexts();
		final GroupVector<DecryptionProof, ZqGroup> pi_dec = verifiableDecryptions.getDecryptionProofs();
		final int N = C.size();
		final int l = C.getElementSize();

		checkArgument(1 <= N, "There must be at least one ciphertext.");
		checkArgument(verifiableDecryptions.get_N() == N, "There must be as many verifiable decryptions as ciphertexts.");

		checkArgument(0 < l, "The ciphertexts must have at least 1 element.");
		checkArgument(verifiableDecryptions.get_l() == l, "The verifiable decryptions must have the same size l as the ciphertexts.");
		checkArgument(l <= pk.size(), "The ciphertexts must have at most as many elements as the public key.");

		final GqGroup gqGroup = C.getGroup();
		checkArgument(verifiableDecryptions.getGroup().equals(gqGroup), "The verifiable decryptions must have the same group as the ciphertexts.");
		checkArgument(pk.getGroup().equals(gqGroup), "The public key must have the same group as the ciphertexts.");

		// Algorithm
		final Verifiable result = IntStream.range(0, N).mapToObj(i -> {
			final ElGamalMultiRecipientCiphertext c_i = C.get(i);
			final DecryptionProof pi_dec_i = pi_dec.get(i);

			final ElGamalMultiRecipientCiphertext c_i_prime = C_prime.get(i);
			final ElGamalMultiRecipientMessage m = new ElGamalMultiRecipientMessage(c_i_prime.getPhi());
			return decryptionProofService.verifyDecryption(c_i, pk, m, pi_dec_i, i_aux);
		}).reduce(Verifiable.create(() -> true, "This state is impossible to reach and indicates a bug."), Verifiable::and);

		return result.verify();
	}

	@Override
	public ExponentiationProof genExponentiationProof(final GroupVector<GqElement, GqGroup> bases, final ZqElement exponent,
			final GroupVector<GqElement, GqGroup> exponentiations, final List<String> auxiliaryInformation) {
		return exponentiationProofService.genExponentiationProof(bases, exponent, exponentiations, auxiliaryInformation);
	}

	@Override
	public boolean verifyExponentiation(final GroupVector<GqElement, GqGroup> bases, final GroupVector<GqElement, GqGroup> exponentiations,
			final ExponentiationProof proof, final List<String> auxiliaryInformation) {
		return exponentiationProofService.verifyExponentiation(bases, exponentiations, proof, auxiliaryInformation);
	}

	@Override
	public PlaintextEqualityProof genPlaintextEqualityProof(final ElGamalMultiRecipientCiphertext firstCiphertext,
			final ElGamalMultiRecipientCiphertext secondCiphertext, final GqElement firstPublicKey, final GqElement secondPublicKey,
			final GroupVector<ZqElement, ZqGroup> randomness, final List<String> auxiliaryInformation) {
		return plaintextEqualityProofService
				.genPlaintextEqualityProof(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey, randomness, auxiliaryInformation);
	}

	@Override
	public boolean verifyPlaintextEquality(final ElGamalMultiRecipientCiphertext firstCiphertext,
			final ElGamalMultiRecipientCiphertext secondCiphertext, final GqElement firstPublicKey, final GqElement secondPublicKey,
			final PlaintextEqualityProof plaintextEqualityProof, final List<String> auxiliaryInformation) {
		return plaintextEqualityProofService.verifyPlaintextEquality(firstCiphertext, secondCiphertext, firstPublicKey, secondPublicKey,
				plaintextEqualityProof, auxiliaryInformation);
	}

	@Override
	public SchnorrProof genSchnorrProof(final ZqElement witness, final GqElement statement, final List<String> auxiliaryInformation) {
		return schnorrProofService.genSchnorrProof(witness, statement, auxiliaryInformation);
	}

	@Override
	public boolean verifySchnorrProof(final SchnorrProof proof, final GqElement statement, final List<String> auxiliaryInformation) {
		return schnorrProofService.verifySchnorrProof(proof, statement, auxiliaryInformation);
	}

}
