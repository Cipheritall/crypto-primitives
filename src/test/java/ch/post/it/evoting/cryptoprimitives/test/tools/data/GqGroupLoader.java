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
package ch.post.it.evoting.cryptoprimitives.test.tools.data;

import java.io.IOException;
import java.math.BigInteger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

public class GqGroupLoader {

	private final GqGroup group;

	GqGroupLoader(final String fileName) throws IOException {
		ObjectMapper mapper = new ObjectMapper();
		final JsonNode jsonNode = mapper.readTree(GqGroupLoader.class.getResource(fileName));

		this.group = new GqGroup(new BigInteger(jsonNode.get("p").asText(), 10), new BigInteger(jsonNode.get("q").asText(), 10),
				new BigInteger(jsonNode.get("g").asText(), 10));
	}

	GqGroup getGroup() {
		return this.group;
	}
}
