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
package ch.post.it.evoting.cryptoprimitives.math;

import java.math.BigInteger;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.squareup.jnagmp.Gmp;

/**
 * <p>This class is thread-safe.</p>
 */
public class BigIntegerOperationsService {

	private static final Logger LOG = LoggerFactory.getLogger(BigIntegerOperationsService.class);
	private static final BigIntegerOperations bigIntegerOperations;

	private static boolean gmpInstalled = false;

	static {
		try {
			Gmp.checkLoaded();
			gmpInstalled = true;
			LOG.info("GMP is installed and ready to use");
		} catch (UnsatisfiedLinkError e) {
			LOG.info("GMP is not installed, native code optimisations are not available, integer operations will now take longer");
		}

		if (gmpInstalled) {
			bigIntegerOperations = new BigIntegerOperationsGMP();
		} else {
			bigIntegerOperations = new BigIntegerOperationsJava();
		}
	}

	private BigIntegerOperationsService() {
		throw new UnsupportedOperationException("BigIntegerOperationsService is not supposed to be instantiated");
	}

	static BigInteger modMultiply(final BigInteger n1, final BigInteger n2, final BigInteger modulus) {
		return bigIntegerOperations.modMultiply(n1, n2, modulus);
	}

	public static BigInteger modExponentiate(final BigInteger base, final BigInteger exponent, final BigInteger modulus) {
		return bigIntegerOperations.modExponentiate(base, exponent, modulus);
	}

	public static BigInteger multiModExp(final List<BigInteger> bases, final List<BigInteger> exponents, final BigInteger modulus) {
		return bigIntegerOperations.multiModExp(bases, exponents, modulus);
	}

	public static BigInteger modInvert(final BigInteger n, final BigInteger modulus) {
		return bigIntegerOperations.modInvert(n, modulus);
	}

	static int getJacobi(final BigInteger a, final BigInteger n) {
		return bigIntegerOperations.getJacobi(a, n);
	}
}
