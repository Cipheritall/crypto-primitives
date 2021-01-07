/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.elgamal;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

public class ElGamalUtils {

	//Convert a matrix of values to ciphertexts
	public static List<ElGamalMultiRecipientCiphertext> valuesToCiphertext(Stream<List<Integer>> ciphertextValues, GqGroup group) {
		return ciphertextValues
				.map(values -> values.stream().map(BigInteger::valueOf).map(value -> GqElement.create(value, group)).collect(Collectors.toList()))
				.map(values -> ElGamalMultiRecipientCiphertext.create(values.get(0), values.subList(1, values.size())))
				.collect(Collectors.toList());
	}
}
