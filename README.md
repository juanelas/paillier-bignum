# A node.js implementation of the Paillier cryptosystem

This is a node.js implementation relying on the [node-bignum](https://github.com/justmoon/node-bignum) library by Stephan Thomas. Bignum is an arbitrary precision integral arithmetic for Node.js using OpenSSL. For a pure javascript implementation (although less efficient)  of the Paillier Cryptosystem, please visit [paillier-js](https://github.com/juanelas/paillier-js).

The Paillier cryptosystem, named after and invented by Pascal Paillier in 1999, is a probabilistic asymmetric algorithm for public key cryptography. A notable feature of the Paillier cryptosystem is its homomorphic properties.

## Homomorphic properties

### Homomorphic addition of plaintexts

The product of two ciphertexts will decrypt to the sum of their corresponding plaintexts,

**D( E(m1) · E(m2) ) mod n^2 = m1 + m2 mod n**

The product of a ciphertext with a plaintext raising g will decrypt to the sum of the corresponding plaintexts,

**D( E(m1) · g^(m2) ) mod n^2 = m1 + m2 mod n**

### (pseudo-)homomorphic multiplication of plaintexts

An encrypted plaintext raised to the power of another plaintext will decrypt to the product of the two plaintexts,

**D( E(m1)^(m2) mod n^2 ) = m1 · m2 mod n**,

**D( E(m2)^(m1) mod n^2 ) = m1 · m2 mod n**.

More generally, an encrypted plaintext raised to a constant k will decrypt to the product of the plaintext and the constant,

**D( E(m1)^k mod n^2 ) = k · m1 mod n**.

However, given the Paillier encryptions of two messages there is no known way to compute an encryption of the product of these messages without knowing the private key.

## Key generation

1. Define the bit length of the modulus n, or keyLength in bits.

2. Choose two large prime numbers p and q randomly and independently of each other such that gcd( p·q, (p-1)(q-1) )=1 and n=p·q has a key length of keyLength. For instance:

    1. Generate a random prime p with a bit length of keyLength/2.

    2. Generate a random prime q with a bit length of keyLength/2.

    3. Repeat until satisfy: p != q and n with a bit length of keyLength.

3. Compute λ = lcm(p-1, q-1) with lcm(a,b) = a·b/gcd(a, b).

4. Select generator g where in Z* de n^2. g can be computed as follows (there are other ways):

    * Generate randoms λ and β in Z* of n (i.e. 0<λ<n and 0<β<n).

    * Compute g = ( λ·n + 1 ) β^n mod n^2

5. Compute the following modular multiplicative inverse

    μ = ( L( g^λ mod n^2 ) )^{-1} mod n

    where L(x) = (x-1)/n

The **public** (encryption) **key** is **(n, g)**.

The **private** (decryption) **key** is **(λ, μ)**.

## Encryption

Let m in Z* of n be the clear-text message,

1. Select random r in Z* of n

2. Compute ciphertext as: **c = g^m · r^n mod n^2**

## Decryption

Let c be the ciphertext to decrypt, where c in Z* of n^2

1. Compute the plaintext message as: **m = L( c^λ mod n^2 ) · μ mod n**

## Usage

Every input number should be a string in base 10, an integer, or a BigNum. All the output numbers are instances of BigNum.

```javascript
// import paillier
const paillier = require('paillier.js');

// synchronous creation of a random private, public key pair for the Paillier cyrptosystem
const {publicKey, privateKey} = paillier.generateRandomKeys(3072);

// asynchronous creation of a random private, public key pair for the Paillier cyrptosystem (ONLY from async function)
const {publicKey, privateKey} = await paillier.generateRandomKeysAsync(3072);

// optionally, you can create your public/private keys from known parameters
const publicKey = new paillier.PublicKey(n, g);
const privateKey = new paillier.PrivateKey(lambda, mu, p, q, publicKey);

// encrypt m
let c = publicKey.encrypt(m);

// decrypt c
let d = privateKey.decrypt(c);

// homomorphic addition of two chipertexts (encrypted numbers)
let c1 = publicKey.encrypt(m1);
let c2 = publicKey.encrypt(m2);
let encryptedSum = publicKey.addition(c1, c2);
let sum = privateKey.decrypt(encryptedSum); // m1 + m2

// multiplication by k
let c1 = publicKey.encrypt(m1);
let encryptedMul = publicKey.multiply(c1, k);
let mul = privateKey.decrypt(encryptedMul); // k · m1
```

See usage examples in [example.js](example.js).

## Classes

<dl>
<dt><a href="#PaillierPublicKey">PaillierPublicKey</a></dt>
<dd><p>Class for a Paillier public key</p>
</dd>
<dt><a href="#PaillierPrivateKey">PaillierPrivateKey</a></dt>
<dd><p>Class for Paillier private keys.</p>
</dd>
</dl>

## Functions

<dl>
<dt><a href="#generateRandomKeys">generateRandomKeys(bitLength, simplevariant)</a> ⇒ <code><a href="#KeyPair">KeyPair</a></code></dt>
<dd><p>Generates a pair private, public key for the Paillier cryptosystem in synchronous mode</p>
</dd>
<dt><a href="#generateRandomKeysAsync">generateRandomKeysAsync(bitLength, simplevariant)</a> ⇒ <code>Promise</code></dt>
<dd><p>Generates a pair private, public key for the Paillier cryptosystem in asynchronous mode</p>
</dd>
</dl>

## Typedefs

<dl>
<dt><a href="#KeyPair">KeyPair</a> : <code>Object</code></dt>
<dd></dd>
</dl>

<a name="PaillierPublicKey"></a>

## PaillierPublicKey
Class for a Paillier public key

**Kind**: global class  

* [PaillierPublicKey](#PaillierPublicKey)
    * [new PaillierPublicKey(n, g)](#new_PaillierPublicKey_new)
    * [.bitLength](#PaillierPublicKey+bitLength) ⇒ <code>number</code>
    * [.encrypt(m)](#PaillierPublicKey+encrypt) ⇒ <code>bignum</code>
    * [.addition(...ciphertexts)](#PaillierPublicKey+addition) ⇒ <code>bignum</code>
    * [.multiply(c, k)](#PaillierPublicKey+multiply) ⇒ <code>bignum</code>

<a name="new_PaillierPublicKey_new"></a>

### new PaillierPublicKey(n, g)
Creates an instance of class PaillierPublicKey


| Param | Type | Description |
| --- | --- | --- |
| n | <code>bignum</code> \| <code>stringBase10</code> \| <code>number</code> | the public modulo |
| g | <code>bignum</code> \| <code>stringBase10</code> \| <code>number</code> | the public generator |

<a name="PaillierPublicKey+bitLength"></a>

### paillierPublicKey.bitLength ⇒ <code>number</code>
Get the bit length of the public modulo

**Kind**: instance property of [<code>PaillierPublicKey</code>](#PaillierPublicKey)  
**Returns**: <code>number</code> - - bit length of the public modulo  
<a name="PaillierPublicKey+encrypt"></a>

### paillierPublicKey.encrypt(m) ⇒ <code>bignum</code>
Paillier public-key encryption

**Kind**: instance method of [<code>PaillierPublicKey</code>](#PaillierPublicKey)  
**Returns**: <code>bignum</code> - - the encryption of m with this public key  

| Param | Type | Description |
| --- | --- | --- |
| m | <code>bignum</code> \| <code>stringBase10</code> \| <code>number</code> | a cleartext number |

<a name="PaillierPublicKey+addition"></a>

### paillierPublicKey.addition(...ciphertexts) ⇒ <code>bignum</code>
Homomorphic addition

**Kind**: instance method of [<code>PaillierPublicKey</code>](#PaillierPublicKey)  
**Returns**: <code>bignum</code> - - the encryption of (m_1 + ... + m_2) with this public key  

| Param | Type | Description |
| --- | --- | --- |
| ...ciphertexts | <code>bignums</code> | 2 or more (big) numbers (m_1,..., m_n) encrypted with this public key |

<a name="PaillierPublicKey+multiply"></a>

### paillierPublicKey.multiply(c, k) ⇒ <code>bignum</code>
Pseudo-homomorphic paillier multiplication

**Kind**: instance method of [<code>PaillierPublicKey</code>](#PaillierPublicKey)  
**Returns**: <code>bignum</code> - - the ecnryption of k·m with this public key  

| Param | Type | Description |
| --- | --- | --- |
| c | <code>bignum</code> | a number m encrypted with this public key |
| k | <code>number</code> | a scalar |

<a name="PaillierPrivateKey"></a>

## PaillierPrivateKey
Class for Paillier private keys.

**Kind**: global class  

* [PaillierPrivateKey](#PaillierPrivateKey)
    * [new PaillierPrivateKey(lambda, mu, p, q, publicKey)](#new_PaillierPrivateKey_new)
    * [.bitLength](#PaillierPrivateKey+bitLength) ⇒ <code>number</code>
    * [.n](#PaillierPrivateKey+n) ⇒ <code>bignum</code>
    * [.decrypt(c)](#PaillierPrivateKey+decrypt) ⇒ <code>bignum</code>

<a name="new_PaillierPrivateKey_new"></a>

### new PaillierPrivateKey(lambda, mu, p, q, publicKey)
Creates an instance of class PaillierPrivateKey


| Param | Type | Description |
| --- | --- | --- |
| lambda | <code>bignum</code> \| <code>stringBase10</code> \| <code>number</code> |  |
| mu | <code>bignum</code> \| <code>stringBase10</code> \| <code>number</code> |  |
| p | <code>bignum</code> \| <code>stringBase10</code> \| <code>number</code> | a big prime |
| q | <code>bignum</code> \| <code>stringBase10</code> \| <code>number</code> | a big prime |
| publicKey | [<code>PaillierPublicKey</code>](#PaillierPublicKey) |  |

<a name="PaillierPrivateKey+bitLength"></a>

### paillierPrivateKey.bitLength ⇒ <code>number</code>
Get the bit length of the public modulo

**Kind**: instance property of [<code>PaillierPrivateKey</code>](#PaillierPrivateKey)  
**Returns**: <code>number</code> - - bit length of the public modulo  
<a name="PaillierPrivateKey+n"></a>

### paillierPrivateKey.n ⇒ <code>bignum</code>
Get the public modulo n=p·q

**Kind**: instance property of [<code>PaillierPrivateKey</code>](#PaillierPrivateKey)  
**Returns**: <code>bignum</code> - - the public modulo n=p·q  
<a name="PaillierPrivateKey+decrypt"></a>

### paillierPrivateKey.decrypt(c) ⇒ <code>bignum</code>
Paillier private-key decryption

**Kind**: instance method of [<code>PaillierPrivateKey</code>](#PaillierPrivateKey)  
**Returns**: <code>bignum</code> - - the decryption of c with this private key  

| Param | Type | Description |
| --- | --- | --- |
| c | <code>bignum</code> \| <code>stringBase10</code> | a (big) number encrypted with the public key |

<a name="generateRandomKeys"></a>

## generateRandomKeys(bitLength, simplevariant) ⇒ [<code>KeyPair</code>](#KeyPair)
Generates a pair private, public key for the Paillier cryptosystem in synchronous mode

**Kind**: global function  
**Returns**: [<code>KeyPair</code>](#KeyPair) - - a pair of public, private keys  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| bitLength | <code>number</code> | <code>4096</code> | the bit lenght of the public modulo |
| simplevariant | <code>boolean</code> | <code>false</code> | use the simple variant to compute the generator |

<a name="generateRandomKeysAsync"></a>

## generateRandomKeysAsync(bitLength, simplevariant) ⇒ <code>Promise</code>
Generates a pair private, public key for the Paillier cryptosystem in asynchronous mode

**Kind**: global function  
**Returns**: <code>Promise</code> - - a promise that returns a [KeyPair](#KeyPair) if resolve  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| bitLength | <code>number</code> | <code>4096</code> | the bit lenght of the public modulo |
| simplevariant | <code>boolean</code> | <code>false</code> | use the simple variant to compute the generator |

<a name="KeyPair"></a>

## KeyPair : <code>Object</code>
**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| publicKey | [<code>PaillierPublicKey</code>](#PaillierPublicKey) | a Paillier's public key |
| privateKey | [<code>PaillierPrivateKey</code>](#PaillierPrivateKey) | the associated Paillier's private key |


* * *