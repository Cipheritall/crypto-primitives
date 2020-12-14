package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext.getCiphertext;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientCiphertext;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientMessage;
import ch.post.it.evoting.cryptoprimitives.elgamal.ElGamalMultiRecipientPublicKey;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.Permutation;
import ch.post.it.evoting.cryptoprimitives.random.PermutationService;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;

/**
 * Re-encrypting shuffle service.
 */
public class ShuffleService {

	private final RandomService randomService;
	private final PermutationService permutationService;

	ShuffleService(final RandomService randomService, final PermutationService permutationService) {
		this.randomService = randomService;
		this.permutationService = permutationService;
	}

	/**
	 * Shuffle and re-encrypt a list of ciphertext with the given key.
	 * @param ciphertexts the ciphertexts to re-encrypt and shuffle.
	 * @param publicKey the public key with which to re-encrypt the ciphertexts.
	 * @return a {@link Shuffle} with the result of the re-encrypting shuffle.
	 */
	Shuffle genShuffle(final List<ElGamalMultiRecipientCiphertext> ciphertexts, final ElGamalMultiRecipientPublicKey publicKey) {
		//Verify ciphertext input
		checkNotNull(ciphertexts);
		checkArgument(ciphertexts.stream().allMatch(Objects::nonNull));
		ImmutableList<ElGamalMultiRecipientCiphertext> ciphertextsCopy = ImmutableList.copyOf(ciphertexts);

		checkArgument(!ciphertextsCopy.isEmpty(), "There must be at least one ciphertext."); //This is equivalent to checking that 0 < N
		checkArgument(ciphertextsCopy.stream().map(ElGamalMultiRecipientCiphertext::getGroup).allMatch(ciphertextsCopy.get(0).getGroup()::equals),
				"All ciphertexts must be from the same group.");
		checkArgument(ciphertextsCopy.stream().map(ElGamalMultiRecipientCiphertext::size).allMatch(size -> size == ciphertextsCopy.get(0).size()),
				"All ciphertexts must have the same size.");
		@SuppressWarnings("squid:S00117")
		int N = ciphertextsCopy.size();
		int n = ciphertextsCopy.get(0).size();

		//Verify public key input
		checkNotNull(publicKey);
		int k = publicKey.size();

		//Verify combination of ciphertext and public key inputs
		checkArgument(0 < n);
		checkArgument(n <= k);
		checkArgument(ciphertextsCopy.get(0).getGroup().equals(publicKey.getGroup()));

		//Generate shuffle
		Permutation psi = this.permutationService.genPermutation(N);

		GqGroup group = ciphertextsCopy.get(0).getGroup();
		ZqGroup exponentGroup = ZqGroup.sameOrderAs(group);
		GqElement identity = group.getIdentity();
		List<GqElement> ones = Stream.generate(() -> identity).limit(n).collect(Collectors.toList());
		ElGamalMultiRecipientMessage onesMessage = new ElGamalMultiRecipientMessage(ones);

		ImmutableList<ZqElement> exponents =
				Stream.generate(() ->  randomService.genRandomExponent(exponentGroup)).limit(N).collect(ImmutableList.toImmutableList());
		ImmutableList<ElGamalMultiRecipientCiphertext> shuffledCiphertexts =
				IntStream.range(0, N)
						.mapToObj(i -> getCiphertext(onesMessage, exponents.get(i), publicKey).multiply(ciphertextsCopy.get(psi.get(i))))
						.collect(ImmutableList.toImmutableList());

		return new Shuffle(shuffledCiphertexts, psi, exponents);
	}
}
