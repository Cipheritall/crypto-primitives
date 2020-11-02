package cryptoprimitives.math;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CertaintyLevelTest {

	@Test
	void getCertaintyLevelTest() {
		assertEquals(112, CertaintyLevel.getCertaintyLevel(2048));
		assertEquals(128, CertaintyLevel.getCertaintyLevel(3072));
	}

	@Test
	@DisplayName("with invalid bit length throws IllegalArgumentException")
	void getCertaintyLevelInvalidLength() {
		assertThrows(IllegalArgumentException.class, () -> CertaintyLevel.getCertaintyLevel(4000));
	}
}