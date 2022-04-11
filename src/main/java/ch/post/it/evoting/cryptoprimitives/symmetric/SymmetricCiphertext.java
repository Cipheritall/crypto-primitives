/*
 * Copyright 2022 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives.symmetric;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;

/**
 * A symmetric ciphertext composed of a ciphertext and nonce.
 *
 * <p>Instances of this class are immutable.</p>
 */
public class SymmetricCiphertext {
	private final byte[] ciphertext;
	private final byte[] nonce;

	SymmetricCiphertext(final byte[] ciphertext, final byte[] nonce) {
		checkNotNull(ciphertext);
		checkNotNull(nonce);
		this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
		this.nonce = Arrays.copyOf(nonce, nonce.length);
	}

	public byte[] getCiphertext() {
		return Arrays.copyOf(ciphertext, ciphertext.length);
	}

	public byte[] getNonce() {
		return Arrays.copyOf(nonce, nonce.length);
	}
}
