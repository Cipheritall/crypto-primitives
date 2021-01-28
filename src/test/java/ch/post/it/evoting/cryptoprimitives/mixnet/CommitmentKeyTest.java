/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class CommitmentKeyTest {

	private static GqGroupGenerator generator;

	private GqElement h;
	private List<GqElement> gs;

	@BeforeAll
	static void setUpAll() {
		GqGroup gqGroup = GqGroupTestData.getGroup();
		generator = new GqGroupGenerator(gqGroup);
	}

	@BeforeEach
	void setUp() {
		h = generator.genNonIdentityNonGeneratorMember();
		gs = Stream.generate(generator::genNonIdentityNonGeneratorMember).limit(10).collect(Collectors.toList());
	}

	@Test
	@DisplayName("contains the correct commitment key")
	void constructionTest() {
		CommitmentKey commitmentKey = new CommitmentKey(h, gs);

		assertEquals(h, commitmentKey.stream().limit(1).collect(Collectors.toList()).get(0));
		assertEquals(gs, commitmentKey.stream().skip(1).collect(Collectors.toList()));
	}

	@Test
	void constructionFromNullParameterTest() {
		assertThrows(NullPointerException.class, () -> new CommitmentKey(null, gs));
		assertThrows(NullPointerException.class, () -> new CommitmentKey(h, null));

		List<GqElement> gList = new ArrayList<>(gs);
		gList.add(null);
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, gList));
	}

	@Test
	void constructionWithEmptyListTest() {
		List<GqElement> emptyList = new LinkedList<>();
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, emptyList));
	}

	@Test
	void constructionWithElementsFromDifferentGroupsTest() {
		List<GqElement> elements = new LinkedList<>(gs);
		GqGroup differentGroup = GqGroupTestData.getDifferentGroup(h.getGroup());
		GqGroupGenerator differentGroupGenerator = new GqGroupGenerator(differentGroup);
		elements.add(differentGroupGenerator.genNonIdentityNonGeneratorMember());

		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, elements));
	}

	@Test
	void constructionWithHAndGFromDifferentGroupsTest() {
		GqGroup differentGroup = GqGroupTestData.getDifferentGroup(h.getGroup());
		GqGroupGenerator differentGroupGenerator = new GqGroupGenerator(differentGroup);
		List<GqElement> gList = Stream.generate(differentGroupGenerator::genNonIdentityNonGeneratorMember).limit(3).collect(Collectors.toList());
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, gList));
	}

	@Test
	void constructionWithIdentityTest() {
		GqElement identity = h.getGroup().getIdentity();
		List<GqElement> elementsWithIdentity = new LinkedList<>(gs);
		elementsWithIdentity.add(identity);

		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(identity, gs));
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, elementsWithIdentity));
	}

	@Test
	void constructionWithGeneratorTest() {
		GqElement generator = h.getGroup().getGenerator();
		List<GqElement> elementsWithIdentity = new LinkedList<>(gs);
		elementsWithIdentity.add(generator);

		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(generator, gs));
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, elementsWithIdentity));
	}
}
