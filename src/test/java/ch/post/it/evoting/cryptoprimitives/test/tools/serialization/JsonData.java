package ch.post.it.evoting.cryptoprimitives.test.tools.serialization;

import static com.google.common.base.Preconditions.checkNotNull;

import java.math.BigInteger;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import lombok.Getter;

/**
 * Represents one of the general object present in the json test files and provides utility method to convert data to the supported types.
 */
@Getter
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
	 *
	 * @param field The name of the field to search for.
	 * @param clazz The target class to convert the field to.
	 * @param <T>   The type representing the target {@code clazz}.
	 * @return The converted json field.
	 */
	public <T> T get(final String field, final Class<T> clazz) {
		checkNotNull(field, "field can not be null.");
		checkNotNull(clazz, "Target class can not be null");

		if (clazz.equals(BigInteger.class)) {
			return clazz.cast(getBigInteger(field));
		} else if (clazz.equals(BigInteger[].class)) {
			return clazz.cast(getBigIntegerArray(field));
		} else if (clazz.equals(BigInteger[][].class)) {
			return clazz.cast(getBigIntegerArrayArray(field));
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
		return new JsonData(jsonNode.get(field));
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
}


