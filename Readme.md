# Crypto-Primitives

## What is the content of this repository?
Cryptographic algorithms play a pivotal role in the Swiss Post Voting System: ensuring their faithful implementation is crucially important. The crypto-primitives library provides a robust and misuse-resistant library implementing some of the Swiss Post Voting System's cryptographic algorithms. We base our library upon a mathematically [precise and unambiguous specification](cryptographic_primitives_specification.pdf). Our pseudo-code description of the cryptographic algorithms—inspired by [Haenni et al.](https://arbor.bfh.ch/13834/)—aims to bridge the representational gap between mathematics and code.

An essential part of the crypto-primitives library is the implementation of the [Bayer-Groth Mix net](http://www0.cs.ucl.ac.uk/staff/J.Groth/MinimalShuffle.pdf). Verifiable mix nets underpin most modern e-voting schemes since they hide the relationship between encrypted votes (potentially linked to the voter's identifier) and decrypted votes. A re-encryption mix net consists of a sequence of mixers, each of which shuffles and re-encrypts an input ciphertext and returns a different ciphertext list containing the same plaintexts. Each mixer proves knowledge of the permutation and the randomness (without revealing them to the verifier). The verifier checks these proofs to guarantee that no mixer added, deleted, or modified a vote.

We augment our specification with test values obtained from an independent implementation of the pseudo-code algorithms: our code validates against [these test values](./src/test/resources) to increase our confidence in the implementation's correctness. The specification embeds the test values as JSON files within the document.

## Under which license is this code available? 
The Crypto-primitives are released under Apache 2.0.

## Changes since publication in 2019
We re-implemented the Bayer-Groth mix net with the following objectives in mind:
* making the specification and the code easier to audit
* providing a misuse resistant library to the e-voting developers
* reducing the number of external dependencies and future maintenance costs
* laying the groundwork for future performance optimizations of mathematical operations

## Future work
We plan for the following improvements to the crypto-primitives library:
* Implementing non-interactive zero-knowledge proofs.
* Optimizing mathematical operations using native libraries and specialized algorithms.
* Investigating potential improvements in parametrizing the Bayer-Groth mix net. We parametrize the Bayer-Groth with two parameters (m,n). If m and n have equal size, the Bayer-Groth mix net is memory-optimal. However, setting m=1 is the most efficient setting for computational performance. Moreover, setting m=1 allows for further simplifications since one can omit the Hadamard and the zero arguments in that case. We plan to conduct other performance tests to analyze the memory-performance trade-off.
* Enforcing abstractions in mathematical operations. Currently, we have some unnecessary conversions between abstract mathematical objects (such as GqElements) and plain values (such as BigIntegers). We should work more strictly with mathematically abstract classes.
* Developing a clear naming convention for the translation of mathematical notations to code and using it consistently across the codebase.
* Investigating the usage of a "context" object that encapsulates values that do not change between protocol executions (group parameters, security level, etc.).
* Removing the restrictions on the public and secret key domain. Currently, we prevent values of 0 and 1 for the secret key as an additional defense; however, excluding 0 and 1 leads to some tricky edge cases (which are theoretically possible but extremely unlikely). Therefore, we plan to remove the restrictions both on the public and the secret key.
* Implementing the ByteArrayToString method. This method is currently not used; therefore, we did not implement it yet.
* Making some randomized unit tests more robust. In very rare cases, some unit tests fail for exceptional edge cases. If you encounter a failure, repeat the unit test.