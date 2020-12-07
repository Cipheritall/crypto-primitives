package ch.post.it.evoting.cryptoprimitives.test.tools.serialization;

import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import lombok.Getter;

/**
 * General deserialization of json test files according to the schema defined in the specifications.
 */
@Getter
public final class TestParameters {

	private String description;

	@JsonDeserialize(using = JsonDataDeserializer.class)
	private JsonData context;

	@JsonDeserialize(using = JsonDataDeserializer.class)
	private JsonData input;

	@JsonDeserialize(using = JsonDataDeserializer.class)
	private JsonData mocked;

	@JsonDeserialize(using = JsonDataDeserializer.class)
	private JsonData output;

	/**
	 * Parse a json file to a list of TestParameters. The resource has to be on classpath.
	 *
	 * @param resourceName The name of the json file.
	 * @return The list of TestParameters after deserialization of the json file.
	 */
	public static List<TestParameters> fromResource(final String resourceName) {
		final URL url = TestParameters.class.getResource(resourceName);

		try {
			final ObjectMapper jsonMapper = new ObjectMapper();

			return Arrays.asList(jsonMapper.readValue(url, TestParameters[].class));
		} catch (final IOException e) {
			throw new RuntimeException("Read values failed for file " + url.getPath() + ". " + e.getMessage());
		}
	}

	private static final class JsonDataDeserializer extends JsonDeserializer<JsonData> {
		private final ObjectMapper mapper;

		public JsonDataDeserializer() {
			this.mapper = new ObjectMapper();
		}

		@Override
		public JsonData deserialize(final JsonParser jsonParser, final DeserializationContext ctxt) throws IOException {
			final JsonNode root = mapper.readTree(jsonParser);
			return new JsonData(root);
		}
	}

}
