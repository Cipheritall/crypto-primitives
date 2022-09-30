# Changelog

## Release 1.0

The following functionalities and improvements are included in release 1.0:

* [Code, Specification] Improved the RecursiveHash's collision-resistance for nested objects (refers to #YWH-PGM2323-69 mentioned in [GitLab issue #37](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/issues/37)).
* [Code, Specification] Ensured the injective encoding of the associated data in the GenCiphertextSymmetric method (refers to #YWH-PGM2323-70 mentioned in [GitLab issue #37](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/issues/37)).
* [Code, Specification] Ensured the injective encoding of the KDF's additional context information (refers to #YWH-PGM2323-71 mentioned in [GitLab issue #37](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/issues/37)).
* [Code, Specification] Split the algorithm Argon2id into two separate algorithm GenArgon2id and GetArgon2id.
* [Code, Specification] Switched to the EXTENDED (128-bits) security level. Renamed the DEFAULT (112-bits) security level to LEGACY.
* [Code, Specification] Fixed the incorrect Require Statement in the algorithm GenUniqueDecimalStrings.
* [Code, Specification] Added an upper limit on the isSmallPrime algorithm.
* [Code] Allowed hashing of empty lists (necessary for signing XML files).
* [Code] Updated dependencies and third-party libraries.

---

## Release 0.15

Release 0.15 includes some feedback from the Federal Chancellery's mandated experts.
We want to thank the experts for their high-quality, constructive remarks:

* Vanessa Teague (Thinking Cybersecurity), Olivier Pereira (Université catholique Louvain), Thomas Edmund Haines (Australian National University)
* Aleksander Essex (Western University Canada)
* Rolf Haenni, Reto Koenig, Philipp Locher, Eric Dubuis (Bern University of Applied Sciences)

The following functionalities and improvements are included in release 0.15:

* [Code, Specification] Specified and implemented the Argon2id method.
* [Code] Renamed the methods multiply and exponentiate to GetCiphertextProduct and GetCiphertextExponentiation (feedback from Rolf Haenni, Reto Koenig, Philipp Locher, and Eric Dubuis).
* [Code] Updated the library to Java 17.
* [Code] Updated dependencies and third-party libraries.
* [Code] Changed the context data in the GenSignature and VerifySignature methods to Hashable object instead of a single String object.

---

## Release 0.14

Release 0.14 includes some feedback from the Federal Chancellery's mandated experts (see above)

The following functionalities and improvements are included in release 0.14:

* [Code, Specification] Specified and implemented methods for handling digital signatures: key and certificate generation, signing, and verifying a signature (feedback from Vanessa Teague, Olivier Pereira, and Thomas Haines).
* [Code, Specification] Specified and implemented a GenUniqueDecimalStrings method (feedback from Rolf Haenni, Reto Koenig, Philipp Locher, and Eric Dubuis).
* [Code, Specification] Specified and implemented an ElGamal CombinePublicKeys method.
* [Code, Specification] Specified and implemented the Schnorr Proof of knowledge (feedback from Vanessa Teague, Olivier Pereira, and Thomas Haines).
* [Code] Implemented the ByteArrayToString method.
* [Specification] Specified a method for probabilistic primality testing (feedback from Aleksander Essex).
* [Specification] Aligned the definition of Base16, Base32, and Base64 alphabets and made the padding character explicit.

---

## Release 0.13

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

---

## Release 0.12

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

---

## Release 0.11

The following functionalities and improvements are included in release 0.11:

* [Code] Implemented the VerifyDecryptions method.
* [Specification] Simplified the _GetCommitmentVector_ algorithm.
* [Specification] Added the _HashAndSquare_ algorithm.

---

## Release 0.10

The following functionalities and improvements are included in release 0.10:

* Specified a VerifyDecryptions method that verifies a vector of decryptions.
* Implemented exponentiation proof verification.
* Integrated the certainty into the SecurityLevel class.
* Added some minor precondition and robustness checks.

---

## Release 0.9

The following functionalities and improvements are included in release 0.9:

* Implemented exponentiation proof generation.
* Added the method GetVerifiableEncryptionParameters in the ElGamalEncryption scheme.
* Documented a clear naming convention for the translation of mathematical notations to code and applied it consistently across the codebase.
* Outsourced the concatenation of byte arrays in the recursive hash function to a utility function.
* Completed some additional « Ensure » statements in the mix net algorithms description to increase robustness.
* Fixed some minor alignment issues in a few algorithms.

---

## Release 0.8

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