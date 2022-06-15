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

package ch.post.it.evoting.cryptoprimitives.signing;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.function.Predicate;
import java.util.function.Supplier;

import ch.post.it.evoting.cryptoprimitives.hashing.Hash;
import ch.post.it.evoting.cryptoprimitives.hashing.HashFactory;
import ch.post.it.evoting.cryptoprimitives.internal.signing.SignatureKeystoreService;

public class SignatureKeystoreFactory {
	private static final Hash hash = HashFactory.createHash();

	private SignatureKeystoreFactory() {
		//Intentionally left blank
	}

	public static <T extends Supplier<String>> SignatureKeystore<T> createSignatureKeystore(final InputStream keyStoreStream, final String keystoreType,
			final char[] password, final Predicate<KeyStore> keystoreValidator, final T signingAlias){
		return new SignatureKeystoreService<>(keyStoreStream, keystoreType, password, keystoreValidator, signingAlias, hash);
	}
}
