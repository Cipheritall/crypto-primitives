# Crypto-Primitives

## What is the content of this repository?

Cryptographic algorithms play a pivotal role in the Swiss Post Voting System: ensuring their faithful implementation is crucially important. The crypto-primitives library provides a robust and misuse-resistant library implementing some of the Swiss Post Voting System's cryptographic algorithms. We base our library upon a mathematically [precise and unambiguous specification](Crypto-Primitives-Specification.pdf). Our pseudo-code description of the cryptographic algorithms - inspired by [Haenni et al.](https://arbor.bfh.ch/13834/) – aims to bridge the representational gap between mathematics and code.

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

## Code Quality

We strive for excellent code quality and to minimize the risk of bugs and vulnerabilities. We rely on the following tools for code analysis.

| Tool        | Focus                 |
|-------------|-----------------------|
| [SonarQube](https://www.sonarqube.org/)  | Code quality and code security      |
| [Fortify](https://www.microfocus.com/de-de/products/static-code-analysis-sast/overview)  | Static Application Security Testing    |
| [JFrog X-Ray](https://jfrog.com/xray/) | Common vulnerabilities and exposures (CVE) analysis, Open-source software (OSS) license compliance | |

### SonarQube Analysis

We parametrize SonarQube with the built-in Sonar way quality profile. The SonarQube analysis of the crypto-primitives code reveals 0 bugs, 0 vulnerabilities, 0 security hotspots, and 6 code smells.

![SonarQube](SonarQube.jpg)

Out of the 6 code smells:

* 6 code smells concern duplicated blocks in the argument classes. We left the code blocks as is since removing them reduces the code's readability.

Moreover, a high test coverage illustrates the fact that we extensively test the crypto-primitives library.

### Fortify Analysis

The Fortify analysis showed 0 critical, 0 high, 0 medium, and 57 low criticality issues. We manually reviewed all 57 low-criticality issues and assessed them as false positives.

### JFrog X-Ray Analysis

The X-Ray analysis indicates that none of the crypto-primitives' 3rd party dependencies contains known vulnerabilities or non-compliant open source software licenses. As a general principle, we try to minimize external dependencies in cryptographic libraries and only rely on well-tested and widely used 3rd party components.

## Mathematical Variables Naming Convention

We aim for a mathematical naming convention that aligns with the following goals:

* have a consistent naming convention,
* make it easy to map visually between specification variables and code variables,
* guarantee an injective mapping from specification to code (but not necessarily from code to specification),
* prevent overloading common, simple variable names.

### Naming Convention Rules

| Naming Convention Rule                                                                                                                                                       | Argumentation                                                                                                                                                    |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1) Use only ASCII characters.                                                                                                                                                |                                                                                                                                                                  |
| 2) Use snake case.                                                                                                                                                           | Snake case allows to separate words and maintain case. It is not standard for Java but more practical for mathematical notations.                                |
| 3) Keep capitalization.                                                                                                                                                      | Even though capitalization may represent a dimension, it hurts the visual identification of the variable.                                                        |
| 4) Ignore bold fonts and superscript arrows. In case of disambiguation based on dimension, one can append "_vector" or "_matrix".                                            | Bold fonts and superscript arrows represent a dimension; since a variable's type already indicates its dimension, we do not repeat it in the variable's name.    |
| 5) Convert non-Latin characters to their Latin equivalent.                                                                                                                   |                                                                                                                                                                  |
| 6) Capitalize the first letter of Greek characters according to the Greek capitalization.                                                                                    | To differentiate lowercase from uppercase Greek letters.                                                                                                         |
| 7) Everything above a character is considered superscript.                                                                                                                   |                                                                                                                                                                  |
| 8) Append subscripts then superscripts. Apply this rule recursively if needed.                                                                                               |                                                                                                                                                                  |
| 9) Getter, setter and build methods for mathematical variables must use the get_, set_, with_ prefix followed by the variable name.                                          | This rule guarantees consistency with the naming of variables.                                                                                                   |
| 10) Method parameters' names should follow Java best practices. Subsequently, the algorithm implementation converts the parameters' names to the mathematical convention.    | Keep methods readable and self-documented while keeping the specification and implementation aligned.                                                            |
| 11) Keep numeric symbols in mathematical variables, except if the full variable name consists of a numeric symbol, in which case we use the fully spelled out equivalent.    |                                                                                                                                                                  |
| 12) Spell out symbols in the mathematical variable names.

### Naming Convention Examples

![Mathematical Naming Convention Examples](naming_convention_examples.jpg)

## Change Log Release 0.11

The following functionalities and improvements are included in release 0.11:

* [Code] Implemented the VerifyDecryptions method.
* [Specification] Simplified the *GetCommitmentVector* algorithm.

## Change Log Release 0.10

The following functionalities and improvements are included in release 0.10:

* Specified a VerifyDecryptions method that verifies a vector of decryptions.
* Implemented exponentiation proof verification.
* Integrated the certainty into the SecurityLevel class.
* Added some minor precondition and robustness checks.

## Change Log Release 0.9

The following functionalities and improvements are included in release 0.9:

* Implemented exponentiation proof generation.
* Added the method GetVerifiableEncryptionParameters in the ElGamalEncryption scheme.
* Documented a clear naming convention for the translation of mathematical notations to code and applied it consistently across the codebase.
* Outsourced the concatenation of byte arrays in the recursive hash function to a utility function.
* Completed some additional « Ensure » statements in the mix net algorithms description to increase robustness.
* Fixed some minor alignment issues in a few algorithms.

## Change Log Release 0.8

The following functionalities and improvements are included in release 0.8:

* Provided decryption proof generation and verification.
* Specified the exponentiation and plaintext equality proof.
* Improved specification of handling errors in Base32/Base64 encoding (corresponds to Gitlab issue [#1](https://gitlab.com/swisspost-evoting/crypto-primitives/-/issues/1)).
* Fixed handling of empty byte arrays in the method ByteArrayToInteger (corresponds to Gitlab issue [#2](https://gitlab.com/swisspost-evoting/crypto-primitives/-/issues/2)).
* Improved specification of UCS decoding (corresponds to Gitlab issue [#3](https://gitlab.com/swisspost-evoting/crypto-primitives/-/issues/3)).
* Fixed the bounds' domain in GenRandomIntegerWithinBounds (corresponds to Gitlab issue [#6](https://gitlab.com/swisspost-evoting/crypto-primitives/-/issues/6)).
* Removed the exclusion of 0 and 1 when generating exponents (corresponds to Gitlab issue [#7](https://gitlab.com/swisspost-evoting/crypto-primitives/-/issues/7)).
* Clarified the purpose of GenRandomBaseXXString methods (corresponds to Gitlab issue [#8](https://gitlab.com/swisspost-evoting/crypto-primitives/-/issues/8)).
* Decoupled the size of the commitment key and the size of the public key in the mix net.
* Fixed the problem with some randomized unit tests failing for exceptional edge cases.

## Future work

We plan for the following improvements to the crypto-primitives library:

* Optimizing mathematical operations using native libraries and specialized algorithms.
* Investigating potential improvements in parametrizing the Bayer-Groth mix net. We parametrize the Bayer-Groth with two parameters (m,n). If m and n have equal size, the Bayer-Groth mix net is memory-optimal. However, setting m=1 is the most efficient setting for computational performance. Moreover, setting m=1 allows for further simplifications since one can omit the Hadamard and the zero arguments in that case. We plan to conduct other performance tests to analyze the memory-performance trade-off.
* Making the RecursiveHash function collision-resistant across different input domains (corresponds to Gitlab issue [#9](https://gitlab.com/swisspost-evoting/crypto-primitives/-/issues/9)).
* Enforcing abstractions in mathematical operations. Currently, we have some unnecessary conversions between abstract mathematical objects (such as GqElements) and plain values (such as BigIntegers). We should work more strictly with mathematically abstract classes.
* Investigating the usage of a "context" object that encapsulates values that do not change between protocol executions (group parameters, security level, etc.).
* Implementing the ByteArrayToString method. This method is currently not used; therefore, we did not implement it yet.

## Open Issues

The current release has the following open issues:

* Implementing plaintext-equality proofs.

## Additional documentation

You can find additional documents related to the crypto-primitives in the following locations:

| Repositories | Content |
| :------- | :---- |
| [`System specification`](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/blob/master/System/System_Specification.pdf) | System Specification of the e-voting system.   |
| [`Voting protocol`](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/blob/master/Protocol/Swiss_Post_Voting_Protocol_Computational_proof.pdf) | The cryptographic protocol that describes the Swiss Post e-voting system in a mathematical form. |
| [`Voting System architecture`](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/blob/master/System/SwissPost_Voting_System_architecture_document.pdf) | Architecture documentation of the e-voting system. |
| [`Documentation overview`](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation) | Overview of all documentations. |
