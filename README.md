# Paillier
The Paillier cryptosystem, named after and invented by Pascal Paillier in 1999, is a probabilistic asymmetric algorithm for public key cryptography. A notable feature of the Paillier cryptosystem is its homomorphic properties.

Homomorphic properties
======================

A notable feature of the Paillier cryptosystem is its homomorphic properties. Several identities can be described:

Homomorphic addition of plaintexts
----------------------------------

The product of two ciphertexts will decrypt to the sum of their corresponding plaintexts,

D( E(m1, r1) · E(m2, r2) ) mod n^2 = m1 + m2 mod n.

The product of a ciphertext with a plaintext raising g will decrypt to the sum of the corresponding plaintexts,

D( E(m1, r1) · g^(m2) ) mod n^2 = m1 + m2 mod n

Homomorphic multiplication of plaintexts
----------------------------------------

An encrypted plaintext raised to the power of another plaintext will decrypt to the product of the two plaintexts,

D( E(m1, r1)^(m2) mod n^2 ) = m1 · m2 mod n,

D( E(m2, r2)^(m1) mod n^2 ) = m1 · m2 mod n.

More generally, an encrypted plaintext raised to a constant k will decrypt to the product of the plaintext and the constant,

D( E(m1, r1)^k mod n^2 ) = k · m1 mod n.

However, given the Paillier encryptions of two messages there is no known way to compute an encryption of the product of these messages without knowing the private key.


Key generation
==============

1.  Define the bit length of the modulus $n$, often called $keyLength$ in bits.

2.  Choose two large prime numbers $p$ and $q$ randomly and independently of each other such that $\gcd(pq, (p-1)(q-1))=1$ and
    $n=p \cdot q$ has a key length of $keyLength$.

    As long as we want $n$ to have $keyLength$ bits and the maximum bit length of the product $p$ and $q$ is the sum of their bit lengths,    we could, for instance:

    1.  Generate a random prime $p$ with a bit length of $\smash{\frac{keyLength}{2}}$.

    2.  Generate a random prime $q$ with a bit length of $\smash{\frac{keyLength}{2}}$ that satisfies: $p \neq q$, $n$ has a bit length of $keyLength$, and $\gcd(pq, (p-1)(q-1))=1$.

3.  Compute $\lambda=\operatorname{lcm}(p-1,q-1)$ with $\operatorname{lcm}(a,b) = \frac{ab}{\gcd(a,b)}$.

4.  Select generator $g$ where $g \in \mathbb{Z}^{*}_{n^{2}}$. $g$ can be computed as follows (there are other ways):

    -   Generate randoms $\alpha$ and $\beta$ in $\mathbb{Z}^{*}_{n}$ (i.e. $0 < \alpha < n$ and $0 < \beta < n$).

    -   Calculate $g$ as: $g=\left( \alpha n + 1 \right) \beta^n \mod{n^2}$

5.  Compute the following modular multiplicative inverse

    $\mu = \left({\operatorname{L}(g^\lambda \mod{n^2})}\right)^{-1} \mod{n}$

    where $\operatorname{L}(u)=\frac{u-1}{n}$

    This multiplicative inverse exists if and only if a valid generator $g$ was selected in the previous step.

The **public** (encryption) **key** is $(n,g)$.

The **private** (decryption) **key** is $(\lambda,\mu)$.

Encryption
==========

1.  Let $m$ be a message to be encrypted where $m \in \mathbb{Z}_{n}$ (i.e. $0 \le m < n$)

2.  Select random $r$ where $r \in \mathbb{Z}^{*}_{n}$ (i.e. $0 < r < n$)

3.  Compute ciphertext as:

Decryption
==========

1.  Let $c$ be the ciphertext to decrypt, where
    $c \in \mathbb{Z}^{*}_{n^{2}}$ (i.e. $0 < c < n^2$)

2.  Compute the plaintext message as:
