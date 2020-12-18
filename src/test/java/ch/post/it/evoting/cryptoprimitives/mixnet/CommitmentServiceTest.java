/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;
import ch.post.it.evoting.cryptoprimitives.math.ZqGroup;
import ch.post.it.evoting.cryptoprimitives.random.RandomService;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.utils.GqGroupMemberGenerator;

class CommitmentServiceTest {

	private static final int NUM_ELEMENTS = 5; // This must be >= 2
	private static final RandomService randomService = new RandomService();

	private List<ZqElement> validValues;
	private GqGroup gqGroup;
	private ZqGroup zqGroup;
	private ZqElement randomValue;
	private CommitmentKey validCommitmentKey;
	private final CommitmentService commitmentService = new CommitmentService();

	private CommitmentKey genCommitmentKey(GqGroup group, int k) {
		GqGroupMemberGenerator generator = new GqGroupMemberGenerator(group);
		GqElement h = generator.genValidPublicKeyGqElementMember();
		List<GqElement> gList = Stream.generate(generator::genValidPublicKeyGqElementMember).limit(k).collect(Collectors.toList());
		return new CommitmentKey(h, gList);
	}

	@BeforeEach
	void setup() {
		gqGroup = GqGroupTestData.getGroup();
		zqGroup = ZqGroup.sameOrderAs(gqGroup);
		validValues = Stream.generate(() -> ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup)).limit(NUM_ELEMENTS).collect(Collectors.toList());
		randomValue = ZqElement.create(randomService.genRandomInteger(zqGroup.getQ()), zqGroup);
		validCommitmentKey = genCommitmentKey(gqGroup, NUM_ELEMENTS);
	}

	@Test
	void getCommitmentWithNullParameters() {
		assertThrows(NullPointerException.class, () -> commitmentService.getCommitment(null, randomValue, validCommitmentKey));
		assertThrows(NullPointerException.class, () -> commitmentService.getCommitment(validValues, null, validCommitmentKey));
		assertThrows(NullPointerException.class, () -> commitmentService.getCommitment(validValues, randomValue, null));
	}

	@Test
	void getCommitmentWithNullElement() {
		List<ZqElement> elements = validValues;
		elements.set(0, null);

		assertThrows(IllegalArgumentException.class, () -> commitmentService.getCommitment(elements, randomValue, validCommitmentKey));
	}

	@Test
	void getCommitmentWithTooLongListOfValues() {
		List<ZqElement> tooLongList = new ArrayList<>(validValues);
		tooLongList.add(zqGroup.getIdentity());
		assertThrows(IllegalArgumentException.class, () -> commitmentService.getCommitment(tooLongList, randomValue, validCommitmentKey));
	}

	@Test
	void getCommitmentWithCommitmentKeyGroupDifferentOrderThanValuesGroup() {
		GqGroup differentGqGroup = GqGroupTestData.getDifferentGroup(gqGroup);
		CommitmentKey differentCommitmentKey = genCommitmentKey(differentGqGroup, NUM_ELEMENTS);
		assertThrows(IllegalArgumentException.class, () -> commitmentService.getCommitment(validValues, randomValue, differentCommitmentKey));
	}

	@Test
	void getCommitmentWithRandomValueDifferentGroupThanValues() {
		ZqGroup differentZqGroup = new ZqGroup(zqGroup.getQ().multiply(BigInteger.TEN));
		ZqElement differentRandomValue = ZqElement.create(randomService.genRandomInteger(differentZqGroup.getQ()), differentZqGroup);
		assertThrows(IllegalArgumentException.class, () -> commitmentService.getCommitment(validValues, differentRandomValue, validCommitmentKey));
	}

	@Test
	@DisplayName("with elements of different groups to be committed to throws IllegalArgumentException")
	void getCommitmentWithElementsFromDifferentGroups() {
		List<ZqElement> invalidElements = new ArrayList<>(validValues);
		ZqGroup differentZqGroup = ZqGroup.sameOrderAs(GqGroupTestData.getDifferentGroup(gqGroup));
		invalidElements.set(0, differentZqGroup.getIdentity());
		assertThrows(IllegalArgumentException.class, () -> commitmentService.getCommitment(invalidElements, randomValue, validCommitmentKey));
	}

	@RepeatedTest(100)
	void getCommitmentInSameGroupAsCommitmentKey() {
		assertEquals(gqGroup, commitmentService.getCommitment(validValues, randomValue, validCommitmentKey).getGroup());
	}

	@RepeatedTest(100)
	void getCommitmentWithLongerCommitmentKeyYieldsSameResult() {
		CommitmentKey longerCommitmentKey = genCommitmentKey(gqGroup, 2 * NUM_ELEMENTS);
		CommitmentKey exactCommitmentKey = new CommitmentKey(longerCommitmentKey.getH(), longerCommitmentKey.getGElements().subList(0, NUM_ELEMENTS));
		GqElement commitmentExactCK = commitmentService.getCommitment(validValues, randomValue, exactCommitmentKey);
		GqElement commitmentLongerCK = commitmentService.getCommitment(validValues, randomValue, longerCommitmentKey);
		assertEquals(commitmentExactCK, commitmentLongerCK);
	}

	@Test
	void getCommitmentWithSpecificValues() {
		GqGroup specificGqGroup = new GqGroup(BigInteger.valueOf(23), BigInteger.valueOf(11), BigInteger.valueOf(6));
		ZqGroup specificZqGroup = ZqGroup.sameOrderAs(specificGqGroup);
		// a = (2, 10)
		List<ZqElement> a = new ArrayList<>();
		a.add(ZqElement.create(BigInteger.valueOf(2), specificZqGroup));
		a.add(ZqElement.create(BigInteger.valueOf(10), specificZqGroup));
		// r = 5
		ZqElement r = ZqElement.create(BigInteger.valueOf(5), specificZqGroup);
		// ck = (2, 3, 4)
		List<GqElement> gElements = new ArrayList<>(2);
		GqElement h = GqElement.create(BigInteger.valueOf(2), specificGqGroup);
		gElements.add(GqElement.create(BigInteger.valueOf(3), specificGqGroup));
		gElements.add(GqElement.create(BigInteger.valueOf(4), specificGqGroup));
		CommitmentKey ck = new CommitmentKey(h, gElements);
		// c = 3
		GqElement expected = GqElement.create(BigInteger.valueOf(3), specificGqGroup);

		assertEquals(expected, commitmentService.getCommitment(a, r, ck));
	}
}
