/*
 * HEADER_LICENSE_OPEN_SOURCE
 */
package ch.post.it.evoting.cryptoprimitives.mixnet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;

import ch.post.it.evoting.cryptoprimitives.ConversionService;
import ch.post.it.evoting.cryptoprimitives.HashService;
import ch.post.it.evoting.cryptoprimitives.Hashable;
import ch.post.it.evoting.cryptoprimitives.HashableBigInteger;
import ch.post.it.evoting.cryptoprimitives.HashableList;
import ch.post.it.evoting.cryptoprimitives.HashableString;
import ch.post.it.evoting.cryptoprimitives.SameGroupVector;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;

/**
 * Represents a public key of {@link GqElement}s that is used for the calculation of a commitment. Instances of this class are immutable.
 *
 * <p>A commitment key is of the form (h, g<sub>1</sub>, ..., g<sub>k</sub>)</p>
 */
class CommitmentKey implements HashableList {

	static final String HASH_CONSTANT = "commitmentKey";
	private final GqGroup group;
	private final GqElement h;
	private final SameGroupVector<GqElement, GqGroup> gElements;

	/**
	 * Creates a {@link CommitmentKey} object.
	 * <p>
	 * All elements of the commitment key have to comply with the following.
	 * <ul>
	 *     <li>be non-null</li>
	 *     <li>be different from 1</li>
	 *     <li>be different from the generator of the group they belong to</li>
	 *     <li>belong to the same {@link GqGroup}</li>
	 * </ul>
	 *
	 * @param h         the h element of this commitment key
	 * @param gElements the list of g elements contained by this commitment key
	 */
	CommitmentKey(GqElement h, List<GqElement> gElements) {
		//Validate h
		checkNotNull(h);
		checkArgument(!h.equals(h.getGroup().getIdentity()), "h cannot be 1");
		checkArgument(!h.equals(h.getGroup().getGenerator()), "h cannot be equal to the group generator");

		//Validate gElements
		checkNotNull(gElements);
		checkArgument(gElements.stream().noneMatch(Objects::isNull), "A commitment key cannot contain null elements");
		SameGroupVector<GqElement, GqGroup> gs = new SameGroupVector<>(gElements);

		checkArgument(!gs.isEmpty(), "No g element provided");
		checkArgument(gs.getGroup().equals(h.getGroup()), "All g elements must have the same group as h");
		checkArgument(gs.stream().noneMatch(element -> element.equals(element.getGroup().getIdentity())),
				"A commitment key cannot contain an identity element.");
		checkArgument(gs.stream().noneMatch(element -> element.equals(element.getGroup().getGenerator())),
				"A commitment key cannot contain an element value equal to the group generator.");

		this.h = h;
		this.group = h.getGroup();
		this.gElements = gs;
	}

	/**
	 * @return the group the elements of the commitment key belong to
	 */
	GqGroup getGroup() {
		return this.group;
	}

	/**
	 * @return the number of g elements
	 */
	int size() {
		return gElements.size();
	}

	/**
	 * Creates a stream of the elements of the commitment key.
	 *
	 * @return a stream of h, g<sub>1</sub>, ..., g<sub>k</sub> in that order
	 */
	public Stream<GqElement> stream() {
		return Stream.concat(Stream.of(this.h), this.gElements.stream());
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		final CommitmentKey that = (CommitmentKey) o;

		return h.equals(that.h) && gElements.equals(that.gElements);
	}

	@Override
	public int hashCode() {
		return Objects.hash(h, gElements);
	}

	@Override
	public String toString() {
		List<String> simpleGElements = gElements.stream().map(GqElement::getValue).map(BigInteger::toString).collect(Collectors.toList());
		return "CommitmentKey{" + "h=" + h + ", g elements=" + simpleGElements + '}';
	}

	@Override
	public ImmutableList<Hashable> toHashableForm() {
		return this.stream().collect(toImmutableList());
	}

	/**
	 * Creates a {@link CommitmentKey} object, with the {@code numberOfCommitmentElements} specifying the commitment key's desired number of
	 * elements.
	 * <p>
	 *
	 * @param numberOfElements k , The desired number of elements of the commitment key. k must be greater than zero.
	 * @param gqGroup          The gqGroup to which the commitment key belongs. {@code gqGroup}
	 */
	static CommitmentKey getVerifiableCommitmentKey(int numberOfElements, GqGroup gqGroup) throws NoSuchAlgorithmException {

		checkArgument(numberOfElements > 0, "The desired number of commitment elements must be greater than zero");
		checkNotNull(gqGroup);

		HashService hashService = new HashService(MessageDigest.getInstance("SHA-256"));

		int count = 0;
		int i = 0;
		Set<BigInteger> v = new LinkedHashSet<>();

		Predicate<BigInteger> validElement = w -> !w.equals(BigInteger.ZERO)
				&& !w.equals(BigInteger.ONE)
				&& !w.equals(gqGroup.getGenerator().getValue())
				&& v.add(w);

		while (count <= numberOfElements) {

			BigInteger u = ConversionService.byteArrayToInteger(hashService.recursiveHash(
					HashableBigInteger.from(gqGroup.getQ()),
					HashableString.from(HASH_CONSTANT),
					HashableBigInteger.from(BigInteger.valueOf(i)),
					HashableBigInteger.from(BigInteger.valueOf(count))));

			BigInteger w = u.modPow(BigInteger.valueOf(2), gqGroup.getP());

			if (validElement.test(w)) {
				count++;
			}
			i++;

		}

		List<GqElement> commitmentKeyElements = v.stream().map(e -> GqElement.create(e, gqGroup)).collect(Collectors.toList());

		return new CommitmentKey(commitmentKeyElements.get(0), commitmentKeyElements.subList(1, commitmentKeyElements.size()));

	}
}
