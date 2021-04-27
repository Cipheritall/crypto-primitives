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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.GroupVector;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientKeyPair;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPrivateKey;
import ch.post.it.evoting.cryptoprimitives.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;

public class ZeroKnowledgeProofService implements ZeroKnowledgeProof {

	private final DecryptionProofService decryptionProofService;

	/**
	 * Instantiates a zero knowledge proof service which operates in a given group. A security provider must already be loaded that contains the
	 * "SHA-256" algorithm.
	 */
	public ZeroKnowledgeProofService() {
		final RandomService randomService = new RandomService();
		HashService hashService;
		try {
			hashService = new HashService(MessageDigest.getInstance("SHA-256"));
		} catch (NoSuchAlgorithmException exception) {
			throw new IllegalStateException("Badly configured message digest instance.");
		}
		decryptionProofService = new DecryptionProofService(randomService, hashService);
	}

	@VisibleForTesting
	public ZeroKnowledgeProofService(final RandomService randomService, final HashService hashService) {
		decryptionProofService = new DecryptionProofService(randomService, hashService);
	}

	@Override
	public VerifiableDecryption genVerifiableDecryptions(final List<ElGamalMultiRecipientCiphertext> ciphertexts,
			final ElGamalMultiRecipientKeyPair keyPair, List<String> auxiliaryInformation) {
		checkNotNull(ciphertexts);
		checkNotNull(keyPair);
		checkNotNull(auxiliaryInformation);

		@SuppressWarnings("squid:S00117")
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> C = GroupVector.from(ciphertexts);
		final ElGamalMultiRecipientPrivateKey sk = keyPair.getPrivateKey();

		// Cross-checks
		checkArgument(!C.isEmpty(), "There must be at least one ciphertext.");
		checkArgument(C.getElementSize() <= sk.size(), "The ciphertexts must be at most as long as the keys in the key pair.");
		checkArgument(C.getGroup().equals(keyPair.getGroup()), "The ciphertexts and the key pair must have the same group.");

		@SuppressWarnings("squid:S00117")
		final GroupVector<ElGamalMultiRecipientCiphertext, GqGroup> CPrime = C.stream()
				.map(c -> c.getPartialDecryption(sk))
				.collect(GroupVector.toGroupVector());
		final ImmutableList<ElGamalMultiRecipientMessage> M = CPrime.stream()
				.map(c -> c.stream().skip(1).collect(Collectors.toList()))
				.map(ElGamalMultiRecipientMessage::new)
				.collect(ImmutableList.toImmutableList());
		final GroupVector<DecryptionProof, ZqGroup> pi = IntStream.range(0, C.size())
				.mapToObj(i -> decryptionProofService.genDecryptionProof(C.get(i), keyPair, M.get(i), auxiliaryInformation))
				.collect(GroupVector.toGroupVector());

		return new VerifiableDecryption(CPrime, pi);
	}
}
