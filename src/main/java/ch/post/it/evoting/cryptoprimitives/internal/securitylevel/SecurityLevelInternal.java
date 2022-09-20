/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package ch.post.it.evoting.cryptoprimitives.internal.securitylevel;

import java.util.function.Supplier;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevel;

/**
 * Represents the possible security levels.
 */
@SuppressWarnings({ "java:S116", "java:S107" })
public enum SecurityLevelInternal implements SecurityLevel {

	TESTING_ONLY(16, 48, SHA3_256.getInstance(), SHAKE256.getInstance(), SHA256Digest::new, AES_GCM_256.getInstance(), RSASSA_PSS.getInstance()),
	LEGACY(112, 2048, SHA3_256.getInstance(), SHAKE256.getInstance(), SHA256Digest::new, AES_GCM_256.getInstance(), RSASSA_PSS.getInstance()),
	EXTENDED(128, 3072, SHA3_256.getInstance(), SHAKE256.getInstance(), SHA256Digest::new, AES_GCM_256.getInstance(), RSASSA_PSS.getInstance());

	private final int securityLevelBits;
	private final int pBitLength;
	private final HashFunction recursiveHashHashFunction;
	private final XOF recursiveHashToZqXOF;
	private final Supplier<Digest> KDFHashFunction;
	private final AEAD symmetricAEAD;
	private final SignatureSupportingAlgorithm signatureSupportingAlgorithm;

	SecurityLevelInternal(final int securityLevelBits, final int pBitLength, final HashFunction recursiveHashHashFunction, final XOF recursiveHashToZqXOF,
			final Supplier<Digest> kdfHashFunction, final AEAD symmetricAEAD, final SignatureSupportingAlgorithm signatureSupportingAlgorithm) {
		this.securityLevelBits = securityLevelBits;
		this.pBitLength = pBitLength;
		this.recursiveHashHashFunction = recursiveHashHashFunction;
		this.recursiveHashToZqXOF = recursiveHashToZqXOF;
		KDFHashFunction = kdfHashFunction;
		this.symmetricAEAD = symmetricAEAD;
		this.signatureSupportingAlgorithm = signatureSupportingAlgorithm;
	}

	public int getSecurityLevelBits() {
		return securityLevelBits;
	}

	public int getPBitLength() {
		return this.pBitLength;
	}

	public HashFunction getRecursiveHashHashFunction() {
		return recursiveHashHashFunction;
	}

	public XOF getRecursiveHashToZqXOF() {
		return recursiveHashToZqXOF;
	}

	public Supplier<Digest> getKDFHashFunction() {
		return KDFHashFunction;
	}

	public AEAD getSymmetricAEAD() {
		return symmetricAEAD;
	}

	public SignatureSupportingAlgorithm getSignatureAlgorithm() {
		return signatureSupportingAlgorithm;
	}
}
