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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.hashing.BoundedHashService;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

public final class MixnetService implements Mixnet {

	private final RandomService randomService;
	private final ShuffleService shuffleService;
	private final HashService hashService;

	public MixnetService() throws NoSuchAlgorithmException {
		hashService = new HashService(MessageDigest.getInstance("SHA-256"));
		randomService = new RandomService();
		final PermutationService permutationService = new PermutationService(randomService);
		shuffleService = new ShuffleService(randomService, permutationService);
	}

	MixnetService(final HashService hashService) {
		this.hashService = checkNotNull(hashService);
		randomService = new RandomService();
		final PermutationService permutationService = new PermutationService(randomService);
		shuffleService = new ShuffleService(randomService, permutationService);
	}

	@Override
	public VerifiableShuffle genVerifiableShuffle(final List<ElGamalMultiRecipientCiphertext> inputCiphertexts,
			final ElGamalMultiRecipientPublicKey publicKey) throws NoSuchAlgorithmException {
		checkNotNull(inputCiphertexts);
		final ImmutableList<ElGamalMultiRecipientCiphertext> ciphertexts = ImmutableList.copyOf(inputCiphertexts);
		checkNotNull(publicKey);

		final int N = ciphertexts.size();

		checkArgument(2 <= N, "N must be >= 2");
		checkArgument(BigInteger.valueOf(N).compareTo(publicKey.getGroup().getQ().subtract(BigInteger.valueOf(3))) <= 0,
				"N must be smaller or equal to q - 3");

		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C = GroupVector.from(ciphertexts);
		final GqGroup gqGroup = publicKey.getGroup();
		checkArgument(gqGroup.equals(C.getGroup()), "Ciphertexts must have the same group as the publicKey");

		checkArgument(ciphertexts.get(0).size() <= publicKey.size(), "Ciphertexts must not contain more elements than the publicKey");

		final Shuffle shuffle = shuffleService.genShuffle(ciphertexts, publicKey);

		@SuppressWarnings("squid:S00117")
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> CPrime = GroupVector.from(shuffle.getCiphertexts());
		final Permutation phi = shuffle.getPermutation();
		final ImmutableList<ZqElement> reEncryptionExponents = shuffle.getReEncryptionExponents();
		final GroupVector<ZqElement, ZqGroup> r = GroupVector.from(reEncryptionExponents);

		final int[] matrixDimensions = MatrixUtils.getMatrixDimensions(N);
		final int m = matrixDimensions[0];
		final int n = matrixDimensions[1];

		final CommitmentKey ck = CommitmentKey.getVerifiableCommitmentKey(n, gqGroup);

		final ShuffleStatement shuffleStatement = new ShuffleStatement(C, CPrime);

		final ShuffleWitness shuffleWitness = new ShuffleWitness(phi, r);

		//shuffleArgument
		final BoundedHashService boundedHashService = new BoundedHashService(this.hashService, gqGroup.getQ().bitLength());
		final ShuffleArgumentService shuffleArgumentService = new ShuffleArgumentService(publicKey, ck, randomService, boundedHashService);
		final ShuffleArgument shuffleArgument = shuffleArgumentService.getShuffleArgument(shuffleStatement, shuffleWitness, m, n);

		return new VerifiableShuffle(shuffle.getCiphertexts(), shuffleArgument);
	}

}
