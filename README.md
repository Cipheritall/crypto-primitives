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

We strive for excellent code quality to minimize the risk of bugs and vulnerabilities. We rely on the following tools for code analysis.

| Tool        | Focus                 |
|-------------|-----------------------|
| [SonarQube](https://www.sonarqube.org/)  | Code quality and code security      |
| [Fortify](https://www.microfocus.com/de-de/products/static-code-analysis-sast/overview)  | Static Application Security Testing    |
| [JFrog X-Ray](https://jfrog.com/xray/) | Common vulnerabilities and exposures (CVE) analysis, Open-source software (OSS) license compliance | |

### SonarQube Analysis

We parametrize SonarQube with the built-in Sonar way quality profile. The SonarQube analysis of the crypto-primitives code reveals 0 bugs, 0 vulnerabilities, 0 security hotspots, and 6 code smells.

![SonarQube](SonarQube.jpg)

Out of the 8 code smells:

* 8 code smells concern duplicated blocks in the argument and proof classes. We left the code blocks as is since removing them reduces the code's readability.

Moreover, a high test coverage illustrates the fact that we extensively test the crypto-primitives library.

### Fortify Analysis

The Fortify analysis showed 0 critical, 0 high, 0 medium, and 60 low criticality issues. We manually reviewed all 60 low-criticality issues and assessed them as false positives.

### JFrog X-Ray Analysis

The X-Ray analysis indicates that none of the crypto-primitives' 3rd party dependencies contains known vulnerabilities or non-compliant open source software licenses. As a general principle, we try to minimize external dependencies in cryptographic libraries and only rely on well-tested and widely used 3rd party components.

## Native Library Support

We support the GNU Multi Precision Arithmetic Library (GMP) for arbitrary-precision integer operations (called BigInteger in the Java programming language). GMP speeds up certain mathematical operations such as modular exponentiation. We recommend the [article by Haenni, Locher, and Gailly](https://e-voting.bfh.ch/app/download/7833228661/HLG19.pdf?t=1601370067) for an overview of popular optimization techniques.

_Linux:_

* Assuming [GMP](https://gmplib.org/) is installed this change should be transparent. If not, install GMP with the relevant package manager.
* No further action is required to benefit from native code optimisations.

_Windows:_

* Create GMP.dll: Build [GMP](https://gmplib.org/) for the relevant Windows architecture.
* Crypto-primitives, building with Maven :
  * Set the environment variable JNA_LIBRARY_PATH=\<location of gmp.dll>
* Crypto-primitives, usage as a third-party dependency
  * Add -Djna.library.path= \<location of gmp.dll> to the Java command line.

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

## Change Log Release 0.14

Release 0.14 includes some feedback from the Federal Chancellery's mandated experts.
We want to thank the experts for their high-quality, constructive remarks:

* Vanessa Teague (Thinking Cybersecurity), Olivier Pereira (Université catholique Louvain), Thomas Edmund Haines (Australian National University)
* Aleksander Essex (Western University Canada)
* Rolf Haenni, Reto Koenig, Philipp Locher, Eric Dubuis (Bern University of Applied Sciences)

The following functionalities and improvements are included in release 0.14:

* [Code, Specification] Specified and implemented methods for handling digital signatures: key and certificate generation, signing, and verifying a signature (feedback from Vanessa Teague, Olivier Pereira, and Thomas Haines).
* [Code, Specification] Specified and implemented a GenUniqueDecimalStrings method (feedback from Rolf Haenni, Reto Koenig, Philipp Locher, and Eric Dubuis).
* [Code, Specification] Specified and implemented an ElGamal CombinePublicKeys method.
* [Code, Specification] Specified and implemented the Schnorr Proof of knowledge (feedback from Vanessa Teague, Olivier Pereira, and Thomas Haines).
* [Code] Implemented the ByteArrayToString method.
* [Specification] Specified a method for probabilistic primality testing (feedback from Aleksander Essex).
* [Specification] Aligned the definition of Base16, Base32, and Base64 alphabets and made the padding character explicit.

## Change Log Release 0.13

Release 0.13 includes some feedback from the Federal Chancellery's mandated experts (see above)

The following functionalities and improvements are included in release 0.13:

* [Code] Implemented the generation and verification of plaintext-equality proofs.
* [Code, Specification] Specified and implemented a KDF and KDFtoZq method based on HKDF (feedback from Vanessa Teague, Olivier Pereira, and Thomas Haines).
* [Code, Specification] Specified and implemented the collision-resistant HashAndSquare method.
* [Code, Specification] Updated the generation of commitment keys (GetVerifiableCommitmentKeys) to use the entire domain of generators (feedback from Vanessa Teague, Olivier Pereira, and Thomas Haines).
* [Code] Updated the unit tests with the test vectors from the collision-resistant hash functions.
* [Code] Aligned the input of the hash functions in the zero-knowledge proofs to the specification (corresponds to Gitlab issue [#10](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/issues/10 )).
* [Code, Specification] Specified and implemented authenticated symmetric encryption (feedback from Rolf Haenni, Reto Koenig, Philipp Locher, and Eric Dubuis).
* [Code, Specification] Specified and implemented the IntegerToString and StringToInteger methods (feedback from Rolf Haenni, Reto Koenig, Philipp Locher, and Eric Dubuis).
* [Code, Specification] Removed compression of excess public keys in ElGamal operations (feedback from Vanessa Teague, Olivier Pereira, and Thomas Haines).
* [Code] Updated dependencies.
* [Specification] Made the usage of Require and Ensure uniform across all algorithms (feedback from Aleksander Essex).
* [Specification] Introduced a specific section for defining the desired security level (feedback from Aleksander Essex, Rolf Haenni, Reto Koenig, Philipp Locher, and Eric Dubuis).
* [Specification] Aligned the usage of various symbols (feedback from Aleksander Essex).
* [Specification] Specified the truncate method (feedback from Aleksander Essex).
* [Specification] Some minor fixes and alignments in various algorithms (feedback from Aleksander Essex).

## Change Log Release 0.12

Release 0.12 includes some feedback from the Federal Chancellery's mandated experts (see above)

The following functionalities and improvements are included in release 0.12:

* [Code] Implemented the GetSmallGroupPrimeMembers and isPrime methods.
* [Code] Ensured thread safety across all services.
* [Code] Various minor improvements.
* [Code] Optimized mathematical operations with the GNU Multi Precision Arithmetic Library (GMP).
* [Specification] Updated to the new version of the Federal Chancellery's Ordinance on Electronic Voting (feedback from Rolf Haenni, Reto Koenig, Philipp Locher, and Eric Dubuis).
* [Specification] Added the GetSmallGroupPrimeMembers and isPrime algorithms. (feedback from Rolf Haenni, Reto Koenig, Philipp Locher, Eric Dubuis, Vanessa Teague, Olivier Pereira, and Thomas Haines)
* [Specification] Made the RecursiveHash function collision-resistant across different input domains (corresponds to Gitlab issue [#9](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/issues/9)).
* [Specification] Specified a RecursiveHashToZq method that outputs a collision resistant hash in the domain of the group Z_q. (feedback from Vanessa Teague, Olivier Pereira, and Thomas Haines).
* [Specification] Masked out excess bits in the GenRandomInteger algorithm (feedback from Vanessa Teague, Olivier Pereira, and Thomas Haines).
* [Specification] Clarified that the algorithm GenEncryptionParameters requires |p| to be a multiple of 8 (feedback from Vanessa Teague, Olivier Pereira, and Thomas Haines).
* [Specification] Specified the Base32 and Base64 alphabet variant (corresponds to Gitlab issue [#17](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/issues/17 )).
* [Specification] Some minor fixes and alignments in various algorithms.

## Change Log Release 0.11

The following functionalities and improvements are included in release 0.11:

* [Code] Implemented the VerifyDecryptions method.
* [Specification] Simplified the _GetCommitmentVector_ algorithm.
* [Specification] Added the _HashAndSquare_ algorithm.

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
* Improved specification of handling errors in Base32/Base64 encoding (corresponds to Gitlab issue [#1](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/issues/1)).
* Fixed handling of empty byte arrays in the method ByteArrayToInteger (corresponds to Gitlab issue [#2](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/issues/2)).
* Improved specification of UCS decoding (corresponds to Gitlab issue [#3](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/issues/3)).
* Fixed the bounds' domain in GenRandomIntegerWithinBounds (corresponds to Gitlab issue [#6](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/issues/6)).
* Removed the exclusion of 0 and 1 when generating exponents (corresponds to Gitlab issue [#7](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/issues/7)).
* Clarified the purpose of GenRandomBaseXXString methods (corresponds to Gitlab issue [#8](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/issues/8)).
* Decoupled the size of the commitment key and the size of the public key in the mix net.
* Fixed the problem with some randomized unit tests failing for exceptional edge cases.

## Future Work

We plan for the following improvements to the crypto-primitives library:

* Investigating potential improvements in parametrizing the Bayer-Groth mix net. We parametrize the Bayer-Groth with two parameters (m,n). If m and n have equal size, the Bayer-Groth mix net is memory-optimal. However, setting m=1 is the most efficient setting for computational performance. Moreover, setting m=1 allows for further simplifications since one can omit the Hadamard and the zero arguments in that case. We plan to conduct other performance tests to analyze the memory-performance trade-off.
* Enforcing abstractions in mathematical operations. Currently, we have some unnecessary conversions between abstract mathematical objects (such as GqElements) and plain values (such as BigIntegers). We should work more strictly with mathematically abstract classes.
* Investigating the usage of a "context" object that encapsulates values that do not change between protocol executions (group parameters, security level, etc.).
* Implementing methods for probabilistic primality testing.

## Open Issues

The current release has the following open issues:

* Change the context data in the GenSignature and VerifySignature methods to Hashable object instead of a single String object.

## Additional Documentation

You can find additional documents related to the crypto-primitives in the following locations:

| Repositories | Content |
| :------- | :---- |
| [`System specification`](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/blob/master/System/System_Specification.pdf) | System Specification of the e-voting system.   |
| [`Voting protocol`](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/blob/master/Protocol/Swiss_Post_Voting_Protocol_Computational_proof.pdf) | The cryptographic protocol that describes the Swiss Post e-voting system in a mathematical form. |
| [`Voting System architecture`](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/blob/master/System/SwissPost_Voting_System_architecture_document.pdf) | Architecture documentation of the e-voting system. |
| [`Documentation overview`](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation) | Overview of all documentations. |
