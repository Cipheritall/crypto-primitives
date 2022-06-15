/*
 * Copyright 2022 Post CH Ltd
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
package ch.post.it.evoting.cryptoprimitives.elgamal;

import static com.google.common.base.Preconditions.checkArgument;

import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import ch.post.it.evoting.cryptoprimitives.hashing.Hashable;
import ch.post.it.evoting.cryptoprimitives.hashing.HashableList;
import ch.post.it.evoting.cryptoprimitives.internal.elgamal.ElGamalMultiRecipientObject;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.math.GroupVector;

/**
 * Represents an ElGamal message containing multiple elements.
 *
 * <p>Instances of this class are immutable.
 */
@SuppressWarnings({ "java:S117" })
public class ElGamalMultiRecipientMessage implements ElGamalMultiRecipientObject<GqElement, GqGroup>, HashableList {

	private final GroupVector<GqElement, GqGroup> messageElements;

	public ElGamalMultiRecipientMessage(final List<GqElement> messageElements) {
		this.messageElements = GroupVector.from(messageElements);
		checkArgument(!this.messageElements.isEmpty(), "An ElGamal message must not be empty.");
	}

	@Override
	public GqGroup getGroup() {
		//A ElGamalMultiRecipientMessage is never empty
		return this.messageElements.getGroup();
	}

	/**
	 * Gets the elements composing this multi recipient message.
	 */
	public GroupVector<GqElement, GqGroup> getElements() {
		return messageElements;
	}

	@Override
	public int size() {
		return this.messageElements.size();
	}

	@Override
	public GqElement get(final int i) {
		return this.messageElements.get(i);
	}

	@Override
	public Stream<GqElement> stream() {
		return this.messageElements.stream();
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ElGamalMultiRecipientMessage that = (ElGamalMultiRecipientMessage) o;
		return messageElements.equals(that.messageElements);
	}

	@Override
	public int hashCode() {
		return Objects.hash(messageElements);
	}

	@Override
	public List<? extends Hashable> toHashableForm() {
		return this.messageElements.toHashableForm();
	}
}
