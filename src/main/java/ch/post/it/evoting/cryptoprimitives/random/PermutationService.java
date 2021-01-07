package ch.post.it.evoting.cryptoprimitives.random;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.stream.IntStream;

public class PermutationService {

	private final RandomService randomService;

	public PermutationService(final RandomService randomService) {
		checkNotNull(randomService);
		this.randomService = randomService;
	}

	/**
	 * Generate a permutation of integers [0, size)
	 *
	 * @param size N, the positive number of values being permuted
	 * @return a Permutation object representing an individual permutation
	 */
	public Permutation genPermutation(int size) {
		checkArgument(size > 0);

		int[] psi = IntStream.range(0, size).toArray();
		for (int i = 0; i < size; i++) {
			int offset = this.randomService.genRandomInteger(BigInteger.valueOf((long) size - i)).intValueExact();
			int tmp = psi[i];
			psi[i] = psi[i + offset];
			psi[i + offset] = tmp;
		}

		return new Permutation(psi);
	}
}
