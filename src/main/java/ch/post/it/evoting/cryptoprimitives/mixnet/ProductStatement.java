/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Objects;

import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.ZqElement;

/**
 * Represents a statement used for the calculation of a product argument.
 */
class ProductStatement {

	private final SameGroupVector<GqElement, GqGroup> commitments;
	private final ZqElement product;
	private final int m;
	private final GqGroup group;

	/**
	 * Instantiates a {@link ProductStatement} with the given commitments and product.
	 * <p>
	 * Both - the commitments and the product - must be non null and have the same order <i>q</i>.
	 *
	 * @param commitments <b><i>c</i></b><sub>A</sub>, a vector of {@link GqElement}s
	 * @param product     <i>b</i>, a {@link ZqElement}
	 */
	ProductStatement(final SameGroupVector<GqElement, GqGroup> commitments, final ZqElement product) {
		checkNotNull(commitments);
		checkNotNull(product);
		checkArgument(commitments.getGroup().hasSameOrderAs(product.getGroup()),
				"The commitments and the product must have the same order q.");

		this.commitments = commitments;
		this.product = product;
		this.m = commitments.size();
		this.group = commitments.getGroup();
	}

	SameGroupVector<GqElement, GqGroup> getCommitments() {
		return commitments;
	}

	ZqElement getProduct() {
		return product;
	}

	int getM() {
		return this.m;
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
		ProductStatement that = (ProductStatement) o;
		return commitments.equals(that.commitments) && product.equals(that.product);
	}

	@Override
	public int hashCode() {
		return Objects.hash(commitments, product);
	}
}
