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
package ch.post.it.evoting.cryptoprimitives.test.tools.data;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public final class PayloadSigner {

	private PayloadSigner() {
		// static usage only
	}

	public static byte[] signPayload(final PrivateKey privateKey, final byte[] payload)
			throws Exception {
		final Signature sig = Signature.getInstance("SHA1WithRSA");
		sig.initSign(privateKey);
		sig.update(payload);
		return sig.sign();
	}

	public static boolean verifyPayload(final PublicKey publicKey, final byte[] payload, final byte[] signature)
			throws Exception {
		final Signature sig = Signature.getInstance("SHA1WithRSA");
		sig.initVerify(publicKey);
		sig.update(payload);
		return sig.verify(signature);
	}
}
