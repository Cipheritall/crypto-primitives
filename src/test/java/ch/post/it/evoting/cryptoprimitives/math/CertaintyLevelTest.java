/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.math;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class CertaintyLevelTest {

	@Test
	void getCertaintyLevelTest() {
		assertEquals(112, CertaintyLevel.getCertaintyLevel(2048));
		assertEquals(128, CertaintyLevel.getCertaintyLevel(3072));
	}

	@Test
	void getCertaintyLevelSmallerLength() {
		assertEquals(80, CertaintyLevel.getCertaintyLevel(1000));
	}

	@Test
	void getCertaintyLevelInvalidLength() {
		assertThrows(IllegalArgumentException.class, () -> CertaintyLevel.getCertaintyLevel(-1));
	}
}