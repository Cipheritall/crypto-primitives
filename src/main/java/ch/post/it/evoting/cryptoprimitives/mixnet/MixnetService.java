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
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.mixnet.CommitmentKeyService.canGenerateKey;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

public final class MixnetService implements Mixnet {

	private final RandomService randomService;
	private final ShuffleService shuffleService;
	private final HashService hashService;
	private final HashService shuffleHashService;
	private final CommitmentKeyService commitmentKeyService;

	/**
	 * Instantiates a mixnet service. A security provider must already be loaded containing the "SHA-256" algorithm.
	 */
	public MixnetService() {
		try {
			this.hashService = new HashService(MessageDigest.getInstance("SHA-256"));
		} catch (NoSuchAlgorithmException exception) {
			throw new IllegalStateException("Badly configured message digest instance.");
		}
		this.commitmentKeyService = new CommitmentKeyService(hashService);
		this.shuffleHashService = hashService; //Two separate hash services are needed for checking the hash length
		this.randomService = new RandomService();
		final PermutationService permutationService = new PermutationService(randomService);
		this.shuffleService = new ShuffleService(randomService, permutationService);
	}

	/**
	 * Allows to test with a specific bounded shuffleHashService.
	 *
	 * @param shuffleHashService the hash service to use for the shuffle proof. Not null.
	 */
	@VisibleForTesting
	public MixnetService(final HashService shuffleHashService) {
		checkNotNull(shuffleHashService);
		try {
			this.hashService = new HashService(MessageDigest.getInstance("SHA-256"));
		} catch (NoSuchAlgorithmException exception) {
			throw new IllegalStateException("Badly configured message digest instance.");
		}
		this.commitmentKeyService = new CommitmentKeyService(hashService);
		this.shuffleHashService = shuffleHashService;
		this.randomService = new RandomService();
		final PermutationService permutationService = new PermutationService(randomService);
		this.shuffleService = new ShuffleService(randomService, permutationService);
	}

	@Override
	public VerifiableShuffle genVerifiableShuffle(final List<ElGamalMultiRecipientCiphertext> inputCiphertexts,
			final ElGamalMultiRecipientPublicKey publicKey) {
		checkNotNull(inputCiphertexts);
		checkNotNull(publicKey);

		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C = GroupVector.from(inputCiphertexts);

		//Ensure
		final int N = C.size();
		checkArgument(2 <= N, "N must be >= 2");
		checkArgument(0 <= C.getElementSize(), "Ciphertexts must contain at least one element.");
		checkArgument(C.getElementSize() <= publicKey.size(), "Ciphertexts must not contain more elements than the publicKey");
		checkArgument(canGenerateKey(C.size(), C.getGroup()), "N must be smaller or equal to q - 3");

		final BigInteger q = C.getGroup().getQ();
		checkArgument(shuffleHashService.getHashLength() * Byte.SIZE < q.bitLength(),
				"The hash service's bit length must be smaller than the bit length of q.");

		//Group checking
		checkArgument(publicKey.getGroup().equals(C.getGroup()), "Ciphertexts must have the same group as the publicKey");
		final GqGroup gqGroup = publicKey.getGroup();

		//Algorithm
		final Shuffle shuffle = shuffleService.genShuffle(C, publicKey);

		@SuppressWarnings("squid:S00117")
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> CPrime = GroupVector.from(shuffle.getCiphertexts());
		final Permutation phi = shuffle.getPermutation();
		final ImmutableList<ZqElement> reEncryptionExponents = shuffle.getReEncryptionExponents();
		final GroupVector<ZqElement, ZqGroup> r = GroupVector.from(reEncryptionExponents);

		final int[] matrixDimensions = MatrixUtils.getMatrixDimensions(N);
		final int m = matrixDimensions[0];
		final int n = matrixDimensions[1];

		final CommitmentKey ck = commitmentKeyService.getVerifiableCommitmentKey(n, gqGroup);

		final ShuffleStatement shuffleStatement = new ShuffleStatement(C, CPrime);

		final ShuffleWitness shuffleWitness = new ShuffleWitness(phi, r);

		//shuffleArgument
		final ShuffleArgumentService shuffleArgumentService = new ShuffleArgumentService(publicKey, ck, randomService, shuffleHashService);
		final ShuffleArgument shuffleArgument = shuffleArgumentService.getShuffleArgument(shuffleStatement, shuffleWitness, m, n);

		return new VerifiableShuffle(GroupVector.from(shuffle.getCiphertexts()), shuffleArgument);
	}

	@Override
	public VerificationResult verifyShuffle(final List<ElGamalMultiRecipientCiphertext> ciphertexts,
			final List<ElGamalMultiRecipientCiphertext> shuffledCiphertexts, final ShuffleArgument shuffleArgument,
			final ElGamalMultiRecipientPublicKey publicKey) {
		checkNotNull(ciphertexts);
		checkNotNull(shuffledCiphertexts);
		checkNotNull(shuffleArgument);
		final ElGamalMultiRecipientPublicKey pk = checkNotNull(publicKey);

		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C = GroupVector.from(ciphertexts);
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C_prime = GroupVector.from(shuffledCiphertexts);

		// Ensure
		final int k = pk.size();
		final int l = C.getElementSize();
		final int N = C.size();
		checkArgument(2 <= N, "N must be >= 2");
		checkArgument(0 <= l, "Ciphertexts must contain at least one element.");
		checkArgument(l <= k, "Ciphertexts must not contain more elements than the publicKey");
		checkArgument(canGenerateKey(C.size(), C.getGroup()), "N must be smaller or equal to q - 3");

		// Group checking
		checkArgument(C.getGroup().equals(C_prime.getGroup()), "The shuffled and re-encrypted ciphertexts must have the same group than the un-shuffled ciphertexts.");
		checkArgument(C.getGroup().equals(shuffleArgument.getGroup()), "The ciphertexts and the shuffle argument must have the same group.");
		checkArgument(C.getGroup().equals(pk.getGroup()), "The public key and the ciphertexts must have to the same group.");

		// Dimension checking
		checkArgument(C.getElementSize() == C_prime.getElementSize(), "All ciphertexts must have the same number of elements.");
		checkArgument(C.size() == C_prime.size(), "There must be as many shuffled and re-encrypted ciphertexts, as un-shuffled ciphertexts.");
		final GqGroup gqGroup = C.getGroup();


		// Operations
		final int[] matrixDimensions = MatrixUtils.getMatrixDimensions(N);
		final int m = matrixDimensions[0];
		final int n = matrixDimensions[1];

		final CommitmentKey ck = commitmentKeyService.getVerifiableCommitmentKey(n, gqGroup);
		final ShuffleStatement shuffleStatement = new ShuffleStatement(C, C_prime);

		final ShuffleArgumentService shuffleArgumentService = new ShuffleArgumentService(pk, ck, randomService, shuffleHashService);

		return shuffleArgumentService.verifyShuffleArgument(shuffleStatement, shuffleArgument, m, n);
	}

}
