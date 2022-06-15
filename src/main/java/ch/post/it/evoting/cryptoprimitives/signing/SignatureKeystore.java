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

import java.security.SignatureException;
import java.util.function.Supplier;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;

public interface SignatureKeystore<T extends Supplier<String>> {

	/**
	 * Generates a signature for the given message.
	 *
	 * @param message               to be signed. Must be non-null.
	 * @param additionalContextData to add to signature. Must be non-null. May be empty.
	 * @return the signature for the message as a byte array
	 * @throws SignatureException if the message is timestamped at a date the certificate is not valid for.
	 */
	byte[] generateSignature(Hashable message, Hashable additionalContextData) throws SignatureException;

	/**
	 * Verifies that a signature is valid and from the expected authority.
	 *
	 * @param signerAlias           of the component that sent the message. Must be present in the keystore. Must be non-null.
	 * @param message               that was signed. Must be non-null.
	 * @param additionalContextData to add to signature. Must be non-null. May be empty.
	 * @param signature             of the message. Must be non-null.
	 * @return true if the signature is valid and the message has a timestamp during which the certificate was valid, false otherwise.
	 * @throws NullPointerException if message is null or if the certificate for the authorityId is not found.
	 * @throws SignatureException   if the message is timestamped at a date the certificate is not valid for.
	 */
	boolean verifySignature(T signerAlias, Hashable message, Hashable additionalContextData, byte[] signature)
			throws SignatureException;

}
