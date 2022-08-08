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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import ch.post.it.evoting.cryptoprimitives.internal.signing.CertificateInfo;

/**
 * Supporting algorithms for signature generation.
 */
public interface SignatureSupportingAlgorithm {
	KeyPair genKeyPair();

	/**
	 * Creates a certificate for the public key, signed by the private key, as a self-signed x.509 certificate
	 * @param keyPair contains the public key to create a certificate for, and the private key with which to sign the certificate.
	 * @param info Defines the additional properties of the certificate, including identity information, validity, and key usage
	 * @return an X509 certificate encoded according to DER
	 */
	X509Certificate getCertificate(final KeyPair keyPair, final CertificateInfo info);

	/**
	 * Signs a message with a private key.
	 * @param privateKey the private key with which to sign the message
	 * @param message the message to sign
	 * @return a byte array representing the signature
	 */
	byte[] sign(final PrivateKey privateKey, final byte[] message);

	/**
	 * Verifies a message's signature.
	 * @param publicKey the public key with which to verify the signature
	 * @param message the message to verify the signature of
	 * @param signature the signature contents
	 * @return true if the signature is valid, false otherwise
	 */
	boolean verify(final PublicKey publicKey, final byte[] message, final byte[] signature);
}
