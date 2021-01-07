/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives;

import java.math.BigInteger;

/**
 * Interface to be implemented by classes whose hashable form is a single {@link BigInteger}.
 */
public interface HashableBigInteger extends Hashable {

	@Override
	BigInteger toHashableForm();

	static HashableBigInteger from(final BigInteger bigInteger) {
		return () -> bigInteger;
	}
}
