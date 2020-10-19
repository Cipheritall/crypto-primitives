/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.test.tools.data;

import java.io.IOException;
import java.math.BigInteger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

public class GqGroupLoader {

	private final GqGroup group;

	public GqGroupLoader(final String fileName) throws IOException {
		ObjectMapper mapper = new ObjectMapper();
		final JsonNode jsonNode = mapper.readTree(GqGroupLoader.class.getResource(fileName));

		this.group = new GqGroup(new BigInteger(jsonNode.get("p").asText(), 10), new BigInteger(jsonNode.get("q").asText(), 10),
				new BigInteger(jsonNode.get("g").asText(), 10));
	}

	public GqGroup getGroup() {
		return this.group;
	}
}
