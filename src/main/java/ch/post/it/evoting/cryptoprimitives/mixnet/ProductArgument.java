/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static ch.post.it.evoting.cryptoprimitives.Validations.allEqual;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

class ProductArgument {

	private final SingleValueProductArgument singleValueProductArgument;
	private GqElement commitmentB;
	private HadamardArgument hadamardArgument;

	private final int m;
	private final int n;
	private final GqGroup group;

	/**
	 * Constructs a {@link ProductArgument}.
	 * <p>
	 * The {@code commitmentB}, {@code hadamardArgument} and {@code singleValueProductArgument} must comply with the following:
	 * <ul>
	 *     <li>belong to the same group</li>
	 *     <li>{@code hadamardArgument} and {@code singleValueProductArgument} must have the same dimension {@code n}</li>
	 * </ul>
	 *
	 * @param commitmentB                the commitment to a vector b. Non-null.
	 * @param hadamardArgument           the Hadamard argument. Non-null.
	 * @param singleValueProductArgument the Single Value Product argument. Non-null.
	 */
	ProductArgument(final GqElement commitmentB, final HadamardArgument hadamardArgument,
			final SingleValueProductArgument singleValueProductArgument) {

		// Null checking.
		checkNotNull(commitmentB);
		checkNotNull(hadamardArgument);
		checkNotNull(singleValueProductArgument);

		// Cross group checking.
		final List<GqGroup> gqGroups = Arrays.asList(commitmentB.getGroup(), hadamardArgument.getGroup(), singleValueProductArgument.getGroup());
		checkArgument(allEqual(gqGroups.stream(), g -> g),
				"The commitment b, Hadamard argument and single value product argument groups must have the same order.");

		// Cross dimension checking.
		checkArgument(hadamardArgument.getN() == singleValueProductArgument.getN(),
				"The Hadamard and single value product arguments must have the same dimension n.");

		this.commitmentB = commitmentB;
		this.hadamardArgument = hadamardArgument;
		this.singleValueProductArgument = singleValueProductArgument;
		this.m = hadamardArgument.getM();
		this.n = hadamardArgument.getN();
		this.group = commitmentB.getGroup();
	}

	/**
	 * Constructs a {@link ProductArgument} with only a {@code singleValueProductArgument}. The commitment b and Hadamard argument remains null when
	 * using this constructor.
	 *
	 * @param singleValueProductArgument the Single Value Product Argument. Non-null.
	 */
	ProductArgument(final SingleValueProductArgument singleValueProductArgument) {
		this.singleValueProductArgument = checkNotNull(singleValueProductArgument);
		this.m = 1;
		this.n = singleValueProductArgument.getN();
		this.group = singleValueProductArgument.getGroup();
	}

	GqElement getCommitmentB() {
		return commitmentB;
	}

	HadamardArgument getHadamardArgument() {
		return hadamardArgument;
	}

	SingleValueProductArgument getSingleValueProductArgument() {
		return singleValueProductArgument;
	}

	int getM() {
		return m;
	}

	int getN() {
		return n;
	}

	GqGroup getGroup() {
		return group;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		ProductArgument that = (ProductArgument) o;
		return Objects.equals(commitmentB, that.commitmentB) && Objects.equals(hadamardArgument, that.hadamardArgument)
				&& singleValueProductArgument.equals(that.singleValueProductArgument);
	}

	@Override
	public int hashCode() {
		return Objects.hash(commitmentB, hadamardArgument, singleValueProductArgument);
	}
}
