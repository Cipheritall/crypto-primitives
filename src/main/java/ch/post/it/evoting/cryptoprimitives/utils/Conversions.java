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

package ch.post.it.evoting.cryptoprimitives.utils;

import java.math.BigInteger;

import ch.post.it.evoting.cryptoprimitives.internal.utils.ConversionsInternal;

public interface Conversions {

	/**
	 * Converts a byte array to its BigInteger equivalent.
	 *
	 * @param bytes B, the byte array to convert. Must be non-null and non-empty.
	 * @return a BigInteger corresponding to the provided byte array representation.
	 */
	static BigInteger byteArrayToInteger(final byte[] bytes) {
		return ConversionsInternal.byteArrayToInteger(bytes);
	}

	/**
	 * Converts a BigInteger to a byte array representation.
	 *
	 * @param x the positive BigInteger to convert.
	 * @return the byte array representation of this BigInteger.
	 */
	static byte[] integerToByteArray(final BigInteger x) {
		return ConversionsInternal.integerToByteArray(x);
	}

	/**
	 * Converts a string to a byte array representation.
	 *
	 * @param s S, the string to convert.
	 * @return the byte array representation of the string.
	 */
	static byte[] stringToByteArray(final String s) {
		return ConversionsInternal.stringToByteArray(s);
	}

	/**
	 * Converts a byte array to a {@link String} representation.
	 *
	 * @param b B, the byte array to convert.
	 * @return the string representation of the byte array.
	 * @throws IllegalArgumentException if the byte array does not correspond to a valid sequence of UTF-8 encoding.
	 */
	static String byteArrayToString(final byte[] b) {
		return ConversionsInternal.byteArrayToString(b);
	}

	/**
	 * Converts a decimal {@link String} representation to a {@link BigInteger} representation.
	 *
	 * @param s S, the decimal {@link String} representation to convert. Not Null, not empty and all characters must be decimal characters.
	 * @return x, the {@link BigInteger} representation of the string.
	 * @throws NullPointerException     if the string s is null
	 * @throws IllegalArgumentException if the string s is empty or not a valid decimal representation of a BigInteger.
	 */
	static BigInteger stringToInteger(final String s) {
		return ConversionsInternal.stringToInteger(s);
	}

	/**
	 * Converts a {@link BigInteger} representation to a decimal {@link String} representation.
	 *
	 * @param x, the {@link BigInteger} representation to convert. Not Null, positive (including 0).
	 * @return S, the decimal {@link String} representation of the bigInteger.
	 * @throws NullPointerException     if the bigInteger is null
	 * @throws IllegalArgumentException if the bigInteger is not positive
	 */
	static String integerToString(final BigInteger x) {
		return ConversionsInternal.integerToString(x);
	}

	/**
	 * Converts an {@link Integer} representation to a decimal {@link String} representation.
	 *
	 * @param x, the {@link Integer} representation to convert. Not Null, positive (including 0).
	 * @return S, the decimal {@link String} representation of the Integer.
	 * @throws NullPointerException     if x is null.
	 * @throws IllegalArgumentException if x is not positive.
	 */
	static String integerToString(final Integer x) {
		return ConversionsInternal.integerToString(x);
	}
}
