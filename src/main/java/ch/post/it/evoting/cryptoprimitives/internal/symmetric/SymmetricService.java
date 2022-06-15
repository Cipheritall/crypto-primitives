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
package ch.post.it.evoting.cryptoprimitives.internal.symmetric;

import java.util.List;

import com.google.common.annotations.VisibleForTesting;

import ch.post.it.evoting.cryptoprimitives.internal.math.RandomService;
import ch.post.it.evoting.cryptoprimitives.internal.symmetric.SymmetricAuthenticatedEncryptionService;
import ch.post.it.evoting.cryptoprimitives.symmetric.Symmetric;
import ch.post.it.evoting.cryptoprimitives.symmetric.SymmetricCiphertext;

public class SymmetricService implements Symmetric {

	private final SymmetricAuthenticatedEncryptionService symmetricAuthenticatedEncryptionService;

	/**
	 * Instantiates an authenticated symmetric encryption service.
	 */
	public SymmetricService() {
		final RandomService randomService = new RandomService();

		symmetricAuthenticatedEncryptionService = new SymmetricAuthenticatedEncryptionService(randomService,
				SymmetricAuthenticatedEncryptionService.SymmetricEncryptionAlgorithm.AES256_GCM_NOPADDING);
	}

	@VisibleForTesting
	public SymmetricService(final RandomService randomService) {
		symmetricAuthenticatedEncryptionService = new SymmetricAuthenticatedEncryptionService(randomService,
				SymmetricAuthenticatedEncryptionService.SymmetricEncryptionAlgorithm.AES256_GCM_NOPADDING);
	}

	@Override
	public SymmetricCiphertext genCiphertextSymmetric(final byte[] encryptionKey, final byte[] plaintext, final List<String> associatedData) {
		return symmetricAuthenticatedEncryptionService.genCiphertextSymmetric(encryptionKey, plaintext, associatedData);
	}

	@Override
	public byte[] getPlaintextSymmetric(final byte[] encryptionKey, final byte[] ciphertext, final byte[] nonce, final List<String> associatedData) {
		return symmetricAuthenticatedEncryptionService.getPlaintextSymmetric(encryptionKey, ciphertext, nonce, associatedData);
	}

	@Override
	public int getNonceLength() {
		return symmetricAuthenticatedEncryptionService.getNonceLength();
	}
}
