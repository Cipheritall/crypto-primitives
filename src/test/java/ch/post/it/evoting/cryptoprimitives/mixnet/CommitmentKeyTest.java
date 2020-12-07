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

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.utils.GqGroupMemberGenerator;

class CommitmentKeyTest {

	private static GqGroupMemberGenerator generator;

	private GqElement h;
	private List<GqElement> g;

	@BeforeAll
	static void setUpAll() {
		GqGroup gqGroup = GqGroupTestData.getGroup();
		generator = new GqGroupMemberGenerator(gqGroup);
	}

	@BeforeEach
	void setUp() {
		h = generator.genValidPublicKeyGqElementMember();
		g = Stream.generate(generator::genValidPublicKeyGqElementMember).limit(10).collect(Collectors.toList());
	}

	@Test
	@DisplayName("contains the correct commitment key")
	void constructionTest() {
		CommitmentKey commitmentKey = new CommitmentKey(h, g);

		assertEquals(h, commitmentKey.getH());
		assertEquals(g, commitmentKey.getGElements());
	}

	@Test
	void constructionFromNullParameterTest() {
		assertThrows(NullPointerException.class, () -> new CommitmentKey(null, g));
		assertThrows(NullPointerException.class, () -> new CommitmentKey(h, null));

		List<GqElement> gList = new ArrayList<>(g);
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
		List<GqElement> elements = new LinkedList<>(g);
		GqGroup differentGroup = GqGroupTestData.getDifferentGroup(h.getGroup());
		GqGroupMemberGenerator differentGroupGenerator = new GqGroupMemberGenerator(differentGroup);
		elements.add(differentGroupGenerator.genValidPublicKeyGqElementMember());

		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, elements));
	}

	@Test
	void constructionWithHAndGFromDifferentGroupsTest() {
		GqGroup differentGroup = GqGroupTestData.getDifferentGroup(h.getGroup());
		GqGroupMemberGenerator differentGroupGenerator = new GqGroupMemberGenerator(differentGroup);
		List<GqElement> gList = Stream.generate(differentGroupGenerator::genValidPublicKeyGqElementMember).limit(3).collect(Collectors.toList());
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, gList));
	}

	@Test
	void constructionWithIdentityTest() {
		GqElement identity = h.getGroup().getIdentity();
		List<GqElement> elementsWithIdentity = new LinkedList<>(g);
		elementsWithIdentity.add(identity);

		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(identity, g));
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, elementsWithIdentity));
	}

	@Test
	void constructionWithGeneratorTest() {
		GqElement generator = h.getGroup().getGenerator();
		List<GqElement> elementsWithIdentity = new LinkedList<>(g);
		elementsWithIdentity.add(generator);

		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(generator, g));
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, elementsWithIdentity));
	}
}
