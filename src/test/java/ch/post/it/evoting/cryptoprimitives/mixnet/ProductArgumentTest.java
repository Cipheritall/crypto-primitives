package ch.post.it.evoting.cryptoprimitives.mixnet;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GqGroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;

class ProductArgumentTest {

	@Test
	@DisplayName("Constructing a ProductArgument with null arguments throws a NullPointerException")
	void constructMultiValueProductArgumentWithNullArguments() {

		GqGroup gqGroup = GqGroupTestData.getGroup();
		GqElement commitmentB = new GqGroupGenerator(gqGroup).genMember();
		HadamardArgument hadamardArgument = mock(HadamardArgument.class);
		SingleValueProductArgument singleValueProductArgument = mock(SingleValueProductArgument.class);

		assertAll(
				() -> assertThrows(NullPointerException.class,
						() -> new ProductArgument(null, hadamardArgument, singleValueProductArgument)),
				() -> assertThrows(NullPointerException.class, () -> new ProductArgument(commitmentB, null, singleValueProductArgument)),
				() -> assertThrows(NullPointerException.class, () -> new ProductArgument(commitmentB, hadamardArgument, null)),
				() -> assertThrows(NullPointerException.class, () -> new ProductArgument(null))
		);
	}

}