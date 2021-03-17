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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
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
		PermutationService permutationService = new PermutationService(randomService);
		shuffleService = new ShuffleService(randomService, permutationService);
	}

	MixnetService(final HashService hashService) {
		this.hashService = hashService;
		randomService = new RandomService();
		PermutationService permutationService = new PermutationService(randomService);
		shuffleService = new ShuffleService(randomService, permutationService);
	}

	@Override
	public VerifiableShuffle genVerifiableShuffle(List<ElGamalMultiRecipientCiphertext> inputCiphertexts,
			ElGamalMultiRecipientPublicKey publicKey) throws NoSuchAlgorithmException {
		checkNotNull(inputCiphertexts);
		checkNotNull(publicKey);

		int N = inputCiphertexts.size();

		checkArgument(N >= 2, "N must be >= 2");

		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C = GroupVector.from(inputCiphertexts);
		GqGroup gqGroup = publicKey.getGroup();
		checkArgument(gqGroup.equals(C.getGroup()), "InputCiphertextList must have the same group as publicKey");

		checkArgument(inputCiphertexts.get(0).size() <= publicKey.size(), "The ciphertext must not contain more elements than the publicKey");

		Shuffle shuffle = shuffleService.genShuffle(inputCiphertexts, publicKey);

		@SuppressWarnings("squid:S00117")
		GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> CPrime = GroupVector.from(shuffle.getCiphertexts());
		Permutation phi = shuffle.getPermutation();
		ImmutableList<ZqElement> reEncryptionExponents = shuffle.getReEncryptionExponents();
		GroupVector<ZqElement, ZqGroup> r = GroupVector.from(reEncryptionExponents);

		int[] matrixDimensions = MatrixUtils.getMatrixDimensions(N);
		int m = matrixDimensions[0];
		int n = matrixDimensions[1];

		CommitmentKey ck = CommitmentKey.getVerifiableCommitmentKey(n, gqGroup);

		ShuffleStatement shuffleStatement = new ShuffleStatement(C, CPrime);

		ShuffleWitness shuffleWitness = new ShuffleWitness(phi, r);

		//shuffleArgument
		MixnetHashService mixnetHashService = new MixnetHashService(this.hashService, gqGroup.getQ().bitLength());
		ShuffleArgumentService shuffleArgumentService = new ShuffleArgumentService(publicKey, ck, randomService, mixnetHashService);
		ShuffleArgument shuffleArgument = shuffleArgumentService.getShuffleArgument(shuffleStatement, shuffleWitness, m, n);

		return new VerifiableShuffle(shuffle.getCiphertexts(), shuffleArgument);
	}

}
