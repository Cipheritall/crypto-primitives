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
package ch.post.it.evoting.cryptoprimitives;

import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeAll;

import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.ZqGroupGenerator;

public class TestGroupSetup {
	protected static GqGroup gqGroup;
	protected static GqGroupGenerator gqGroupGenerator;
	protected static GqGroup otherGqGroup;
	protected static GqGroupGenerator otherGqGroupGenerator;

	protected static ZqGroup zqGroup;
	protected static ZqGroupGenerator zqGroupGenerator;
	protected static ZqGroup otherZqGroup;
	protected static ZqGroupGenerator otherZqGroupGenerator;

	protected static final SecureRandom secureRandom = new SecureRandom();

	@BeforeAll
	static void testGroupSetup() {
		// GqGroup and corresponding ZqGroup set up.
		gqGroup = GroupTestData.getGqGroup();
		gqGroupGenerator = new GqGroupGenerator(gqGroup);
		otherGqGroup = GroupTestData.getDifferentGqGroup(gqGroup);
		otherGqGroupGenerator = new GqGroupGenerator(otherGqGroup);
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		zqGroupGenerator = new ZqGroupGenerator(zqGroup);
		otherZqGroup = ZqGroup.sameOrderAs(otherGqGroup);
		otherZqGroupGenerator = new ZqGroupGenerator(otherZqGroup);
	}

}
