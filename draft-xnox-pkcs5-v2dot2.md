---
title: "PKCS #5: Password-Based Cryptography Specification Version 2.2"
category: info

docname: draft-xnox-pkcs5-v2dot2-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - pkcs5
 - pbkdf2
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "xnox/draft-xnox-pkcs5-v2dot2"
  latest: "https://xnox.github.io/draft-xnox-pkcs5-v2dot2/draft-xnox-pkcs5-v2dot2.html"

author:
 -
    fullname: Dimitri John Ledkov
    organization: Chainguard, Inc.
    email: dimitri.ledkov@surgut.co.uk

normative:

informative:
  MORRIS: DOI.10.1145/359168.359172
  SP800-63b: DOI.10.6028/NIST.SP.800-63b
  SP800-132: DOI.10.6028/NIST.SP.800-132
  OWASP:
    target: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    title: OWASP Cheat Sheet Series - Password Storage Cheat Sheet
    author:
      - ins: Cheat Sheets Series Team
        name: Cheat Sheets Series Team
    date: 2025
  HASHCAT:
    target: https://hashcat.net/
    title: hashcat - advanced password recovery
    author:
      - ins: J. Steube
        name: Jens Steube
    date: 2015
  PBKDF2COLLISION:
     target: https://mathiasbynens.be/notes/pbkdf2-hmac
     title: PBKDF2+HMAC hash collisions explained
     author:
       - ins: M. Bynens
         name: Mathias Bynens
     date: 2014
  YESCRYPT:
     target: https://www.openwall.com/yescrypt/
     title: openwall yescrypt - scalable KDF and password hashing scheme
     author:
       - ins: A. Peslyak (Solar Designer)
         name: Alexander Peslyak (Solar Designer)
     date: 2018


--- abstract

This document provides recommendations for the implementation of
password-based cryptography, covering key derivation functions,
encryption schemes, message authentication schemes, and ASN.1 syntax
identifying the techniques.

This document obsoletes {{?RFC8018}}.
--- middle

# Introduction

This document provides recommendations for the implementation of
password-based cryptography, covering the following aspects:

-  key derivation functions
-  encryption schemes
-  message authentication schemes
-  ASN.1 syntax identifying the techniques

The recommendations are intended for general application within computer and
communications systems and, as such, include a fair amount of flexibility. They
are particularly intended for the protection of sensitive information such as
private keys as in CMS {{?RFC5652}} and Asymmetric Key Packages {{?RFC5958}}. It
is expected that application standards and implementation profiles based on
these specifications may include additional constraints.

Other cryptographic techniques based on passwords, such as password-based key
entity authentication and key establishment protocols are outside the scope of
this document.

The password-based key derivation functions described in this document
are not memory-hard and do not offer protection against attacks using
custom hardware. If possible, consider using scrypt {{?RFC7914}},
yescrypt [YESCRYPT] or Argon2 {{?RFC9106}} instead.

Guidelines for the selection of passwords are also outside the scope. This
document supersedes PKCS #5 version 2.1 {{!RFC8018}} and removes techniques
it has previouslly obsoleted.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Notation

{:vspace}
C:
: ciphertext, an octet string

IterationCount:
: iteration count, a positive integer

DerivedKey:
: derived key, an octet string

DerivedKeyLength:
: length in octets of the derived key, a positive integer

EM:
: encoded message, an octet string

Hash:
: underlying hash function

HashLength:
: length in octets of pseudorandom function output, a positive integer

l:
: length in blocks of derived key, a positive integer

IV:
: initialization vector, an octet string

K:
: encryption key, an octet string

KeyDerivationFunction:
: key derivation function

Message:
: message, an octet string

Passwrod:
: password, an octet string

PRF:
: underlying pseudorandom function

PS:
: padding string, an octet string

psLen:
: length in octets of padding string, a positive integer

Salt:
: salt, an octet string

T:
: message authentication code, an octet string

T_1, ..., T_l, U_1, ..., U_c:
: intermediate values, octet strings

`01`, `02`, ..., `08`:
: octets with value 1, 2, ..., 8

\xor:
: bit-wise exclusive-or of two octet strings

`||  ||`:
: octet length operator

`||`:
: concatenation operator

`i..j`:
: substring extraction operator: extracts octets `i` through `j`, `0 <= i <= j`

# Overview

In many applications of public-key cryptography, user security is
ultimately dependent on one or more secret text values or passwords.
Since a password is not directly applicable as a key to any conventional
cryptosystem, however, some processing of the password is required to
perform cryptographic operations with it. Moreover, as passwords are
often chosen from a relatively small space, special care is required in
that processing to defend against search attacks.

A general approach to password-based cryptography, as described by
Morris and Thompson [MORRIS] for the protection of password tables, is
to combine a password with a salt to produce a key. The salt can be
viewed as an index into a large set of keys derived from the password
and need not be kept secret. Although it may be possible for an opponent
to construct a table of possible passwords (a so- called "dictionary
attack"), constructing a table of possible keys will be difficult, since
there will be many possible keys for each password. An opponent will
thus be limited to searching through passwords separately for each salt.

Another approach to password-based cryptography is to construct key
derivation techniques that are relatively expensive, thereby
increasing the cost of exhaustive search. One way to do this is to
include an iteration count in the key derivation technique, indicating
how many times to iterate some underlying function by which keys are
derived. A modest number of iterations (say, 1000) is not likely to be
a burden for legitimate parties when computing a key, but also trivial
to attack with custom hardware.

Whenever possible, please switch from functions described here to
memory-hard function such as scrypt {{?RFC7914}}, yescrypt [YESCRYPT]
or Argon2 {{?RFC9106}} instead.

Salt and iteration count formed the basis for password-based
encryption in PKCS #5 v2.0, and are adopted here as well for the
various cryptographic operations. Thus, password-based key derivation
as defined here is a function of a password, a salt, and an iteration
count, where the latter two quantities need not be kept secret.

From a password-based key derivation function, it is straightforward to
define password-based encryption and message authentication schemes. As
in PKCS #5 v2.0, the password-based encryption schemes here are based on
an underlying, conventional encryption scheme, where the key for the
conventional scheme is derived from the password. Similarly, the
password-based message authentication scheme is based on an underlying
conventional scheme. This two-layered approach makes the password-based
techniques modular in terms of the underlying techniques they can be
based on.

It is expected that the password-based key derivation functions may
find other applications than just the encryption and message
authentication schemes defined here. For instance, one might use the
output produced by key derivation function described here as the
keying material input to HKDF {{?RFC5869}}. Another application is
password checking, where the output of the key derivation function is
stored (along with the salt and iteration count) for the purposes of
subsequent verification of a password.

Throughout this document, a password is considered to be an octet
string of arbitrary length whose interpretation as a text string is
unspecified. In the interest of interoperability, however, it is
recommended that applications follow some common text encoding rules.
ASCII and UTF-8 {{?RFC3629}} are two possibilities. (ASCII is a subset
of UTF-8.)

Although the selection of passwords is outside the scope of this
document, guidelines have been published [SP800-63b] that may well be
taken into account.

# Salt and Iteration Count {#salt-count}

Inasmuch as salt and iteration count are central to the techniques
defined in this document, some further discussion is warranted.

## Salt

A salt in password-based cryptography has traditionally served the
purpose of producing a large set of keys corresponding to a given
password, one of which is selected at random according to the salt. An
individual key in the set is selected by applying a key derivation
function KeyDerivationFunction, as

         DerivedKey = KeyDerivationFunction (Password, Salt)

where output DerivedKey is the derived key, with Password and Salt as
inputs. This has two benefits:

1. It is difficult for an opponent to precompute all the keys, or
   even the most likely keys, corresponding to a dictionary of
   passwords. If the salt is 128 bits long, for instance, there will
   be as many as 2^128 keys for each password. An opponent is thus
   limited to searching for passwords after a password- based
   operation has been performed and the salt is known.

2. It is unlikely that the same key will be selected twice. Again, if
   the salt is 128 bits long, the chance of "collision" between keys
   does not become significant until about 2^64 keys have been
   produced, according to the Birthday Paradox. The fact that
   collisions are unlikely addresses some concerns about interactions
   between multiple uses of the same key that may arise when using
   some encryption and authentication techniques.

In password-based encryption, the party encrypting a message can gain
assurance that these benefits are realized simply by selecting a large
and sufficiently random salt when deriving an encryption key from a
password. A party generating a message authentication code can gain such
assurance in a similar fashion.

The party decrypting a message or verifying a message authentication
code, however, cannot be sure that a salt supplied by another party has
actually been generated at random. It is possible, for instance, that
the salt may have been copied from another password-based operation in
an attempt to exploit interactions between multiple uses of the same
key. For instance, suppose two legitimate parties exchange an encrypted
message, where the encryption key is an 160-bit key derived from a
shared password with some salt. An opponent could take the salt from
that encryption and provide it to one of the parties as though it were
for a 40-bit key. If the party reveals the result of decryption with the
40-bit key, the opponent may be able to solve for the 40-bit key. In the
case that 40-bit key is the first half of the 80-bit key, the opponent
can then readily solve for the remaining 40 bits of the 80-bit key.

To defend against such attacks, avoid multiple uses of the same key. The
salt must not contain data that explicitly distinguishes between
different operations. For example, the salt must not have an additional,
non-random octet that specifies whether the derived key is for
encryption, for message authentication, or for some other operation.

Based on this, the following is recommended for salt generation:

1. The salt must be generated at random and need not be checked for a
   particular format by the party receiving the salt. It should be at
   least sixteen octets (128 bits) long.

2. The salt must not contain any data that explicitly distinguishes
   between different operations, customization string and different
   key lengths.

3. The encoding of a structure that specifies detailed information
   about the derived key, such as the encryption or authentication
   technique, customization string and a sequence number among the
   different keys derived from the password. The particular format of
   the additional data is left to the application.

If a random number generator or pseudorandom generator is not available,
a deterministic alternative for generating the salt must not be made
available.

## Iteration Count

An iteration count has traditionally served the purpose of increasing
the cost of producing keys from a password, thereby also increasing
the difficulty of attack. Mathematically, an iteration count will
increase the security strength of a password by log2(IteractionCount)
bits against trial-based attacks like brute force or dictionary
attacks.

Choosing a reasonable value for the iteration count depends on
environment and circumstances, and varies from application to
application. The computing power of general purpose and bespoke
hardware has significantly increased in its hashing performance. This
has been demonstrated by the hashcat [HASHCAT] software.

This document broadly follows the OWASP Foundation [OWASP]
recommendations, but preffers SHA512:

 * PBKDF2-HMAC-SHA512: 210,000 iterations or higher (recommended)
 * PBKDF2-HMAC-SHA256: 600,000 iterations or higher

The NIST SP 800-63b [SP800-63b] recommends password of minimum 8
characters length and calls for support of maximum 64 characters
length. Given UTF-8 {{?RFC3629}} encoded characters can be up to 4
bytes long, the block size of 512 bits can be often reached by the
password. When block size is exceeded it will result in pre-hashing
the password string to reduce its size, leading to what is known as
PBKDF2 hash collision [PBKDF2COLLISION]. To avoid such collisions this
document recommends to choose PBKDF2-HMAC-SHA512 with at least 210,000
iterations count due to its larger block size and wide
support. PBKDF2-HMAC-SHA256 with at least 600,000 iterations count may
be used when SHA512 is not available.

When choosing iteration count for other PRF functions, consult
benchmarks of commonly available and specialised hardware to have
hashing speed similar to the above rates or slower (thus harder).

# Key Derivation Function

A key derivation function produces a derived key from a base key and
other parameters. In a password-based key derivation function, the
base key is a password, and the other parameters are a salt value and
an iteration count, as outlined in {{salt-count}}.

The primary application of the password-based key derivation functions
defined here is in the encryption schemes in Section 6 and the message
authentication scheme in Section 7.  Other applications are certainly
possible, hence the independent definition of these functions.

A typical application of the key derivation functions defined here
might include the following steps:

  1. Select a Salt and an IterationCount, as outlined in {{salt-count}}.

  2. Select a length in octets for the derived key, DerivedKeyLength.

  3. Apply the key derivation function to the password, the salt, the
     iteration count and the key length to produce a derived key.

  4. Output the derived key.

Only a single key can be derived. Any number of additional keys may
not be derived from a password by varying the salt. If additional keys
are needed use the derived key as input material to and Extract and
Expand function such as HKDF {{?RFC5869}}.

## PBKDF2

PBKDF2 applies a pseudorandom function (see Appendix B.1 for an
example) to derive keys.  The length of the derived key is essentially
unbounded.  (However, the maximum effective search space for the
derived key may be limited by the structure of the underlying
pseudorandom function.  See Appendix B.1 for further discussion.)

    DerivedKey = PBKDF2 (Password, Salt, IterationCount, DerivedKeyLength)

Options

  * PRF - Pseudorandom function (hashLength denotes the length in
    octets of the pseudorandom function output)

Inputs:

  * Password - an octet string

  * Salt - an octet string

  * IterationCount - a positive integer

  * DerivedKeyLength - intended length in octets of the derived key, a
    positive integener, maxumum value (2^32 - 1) * hashLength

Outputs:

  * DerivedKey, a DerivedKeyLength long octet string

Steps:

1. If DerivedKeyLength > (2^32 - 1) * hashLength, output "derived key
   too long" and stop.

2. Let l be the number of hashLength-octet blocks in the derived key,
   rounding up, and let r be the number of octets in the last
   block:

        l = CEILING (DerivedKeyLength / hashLength)
        r = DerivedKeyLength - (l - 1) * hashLength

   Here, CEIL (x) is the "ceiling" function, i.e., the smallest
   integer greater than, or equal to, x.

3. For each block of the derived key apply the function F defined
   below to the Password, the Salt, the IterationCount, and the block
   index to compute the block:

        T_1 = F (Password, Salt, IterationCount, 1)
        T_2 = F (Password, Salt, IterationCount, 2)
        ...
        T_l = F (Password, Salt, IterationCount, l)

   where the function F is defined as the exclusive-or sum of the
   first c iterates of the underlying pseudorandom function PRF
   applied to the password P and the concatenation of the salt S
   and the block index i:

        F (Password, Salt, IterationCount, i) = U_1 \xor U_2 \xor ... \xor U_c

   where

        U_1 = PRF (Password, Salt || INT (i)) ,
        U_2 = PRF (Password, U_1) ,
        ...
        U_c = PRF (Password, U_{c-1}) .

   Here, INT (i) is a four-octet encoding of the integer i, most
   significant octet first.

4. Concatenate the blocks and extract the first DerivedKeyLength
   octets to produce a derived key DerivedKey:

        DerivedKey = T_1 || T_2 ||  ...  || T_l<0..r-1>

5. Output the derived key DerivedKey.

Note: The construction of the function F follows a
"belt-and-suspenders" approach. The iterates U_i are computed
recursively to remove a degree of parallelism from an opponent; they
are exclusive-ored together to reduce concerns about the recursion
degenerating into a small set of values.

# Encryption Scheme

   An encryption scheme, in the symmetric setting, consists of an
   encryption operation and a decryption operation, where the encryption
   operation produces a ciphertext from a message under a key, and the
   decryption operation recovers the message from the ciphertext under
   the same key.  In a password-based encryption scheme, the key is a
   password.

   A typical application of a password-based encryption scheme is a
   private-key protection method, where the message contains private-key
   information, as in PKCS #8.  The encryption schemes defined here
   would be suitable encryption algorithms in that context.

# Message Authentication Schemes

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

This document is based on the {{?RFC8018}}, the IETF republication of PKCS #5 v2.1 from
RSA Laboratories' Public-Key Cryptography Standards (PKCS) series.
