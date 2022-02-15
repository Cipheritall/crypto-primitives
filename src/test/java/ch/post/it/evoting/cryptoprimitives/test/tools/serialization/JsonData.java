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
package ch.post.it.evoting.cryptoprimitives.test.tools.serialization;

import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.Base64;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

/**
 * Represents one of the general object present in the json test files and provides utility method to convert data to the supported types.
 */
public final class JsonData {

	/* The underlying jackson node. */
	private final JsonNode jsonNode;

	public JsonData(final JsonNode jsonNode) {
		this.jsonNode = jsonNode;
	}

	/**
	 * Get a json field by its name and convert to the specified {@code clazz}. The supported target classes are:
	 *
	 * <li>BigInteger</li>
	 * <li>BigInteger[]</li>
	 * <li>BigInteger[][]</li>
	 * <li>String</li>
	 * <li>String[]</li>
	 * <li>byte[]</li>
	 * <li>Boolean</li>
	 * <li>Integer</li>
	 *
	 * @param field The name of the field to search for.
	 * @param clazz The target class to convert the field to.
	 * @param <T>   The type representing the target {@code clazz}.
	 * @return The converted json field.
	 */
	public <T> T get(final String field, final Class<T> clazz) {
		checkNotNull(field, "field cannot be null.");
		checkNotNull(clazz, "Target class cannot be null");

		if (clazz.equals(BigInteger.class)) {
			return clazz.cast(getBigInteger(field));
		} else if (clazz.equals(BigInteger[].class)) {
			return clazz.cast(getBigIntegerArray(field));
		} else if (clazz.equals(BigInteger[][].class)) {
			return clazz.cast(getBigIntegerArrayArray(field));
		} else if (clazz.equals(String.class)) {
			return clazz.cast(jsonNode.get(field).asText());
		} else if (clazz.equals(String[].class)) {
			return clazz.cast(getStringArray(field));
		} else if (clazz.equals(byte[].class)) {
			return clazz.cast(Base64.getDecoder().decode(jsonNode.get(field).asText()));
		} else if (clazz.equals(Boolean.class)) {
			return clazz.cast(jsonNode.get(field).asBoolean());
		} else if (clazz.equals(Integer.class)){
			return clazz.cast(jsonNode.get(field).asInt());
		} else {
			throw new IllegalArgumentException("Unsupported target class.");
		}
	}

	/**
	 * Get the json filed as a JsonData object without further convertion to Java types.
	 *
	 * @param field The name of the field to search for.
	 * @return The "raw" JsonData.
	 */
	public JsonData getJsonData(final String field) {
		return new JsonData(jsonNode.path(field));
	}

	public JsonNode getJsonNode() {
		return jsonNode;
	}

	/**
	 * Calls the jackson {@link JsonNode#toString()} method.
	 *
	 * @return The string representation of this JsonData object.
	 */
	public String toString() {
		return jsonNode.toString();
	}

	private BigInteger getBigInteger(final String field) {
		return stringToBigInteger(jsonNode.get(field).asText());
	}

	private BigInteger[] getBigIntegerArray(final String field) {
		final ArrayNode arrayNode = jsonNode.withArray(field);

		return StreamSupport.stream(arrayNode.spliterator(), false)
				.map(n -> stringToBigInteger(n.asText()))
				.toArray(BigInteger[]::new);
	}

	private BigInteger[][] getBigIntegerArrayArray(final String field) {
		final ArrayNode outerArrayNode = jsonNode.withArray(field);

		return StreamSupport.stream(outerArrayNode.spliterator(), false)
				.map(innerArrayNode -> StreamSupport.stream(innerArrayNode.spliterator(), false)
						.map(n -> stringToBigInteger(n.asText()))
						.toArray(BigInteger[]::new))
				.toArray(BigInteger[][]::new);
	}

	private static BigInteger stringToBigInteger(final String s) {
		if (!s.startsWith("0x")) {
			throw new IllegalArgumentException("Invalid integer format. Must match hexadecimal format starting with: \"0x\".");
		}

		return new BigInteger(s.substring(2), 16);
	}

	private String[] getStringArray(final String field) {
		final ArrayNode arrayNode = jsonNode.withArray(field);

		return StreamSupport.stream(arrayNode.spliterator(), false)
				.map(JsonNode::asText)
				.toArray(String[]::new);
	}
}


