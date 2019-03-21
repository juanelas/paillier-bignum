'use strict';

const bignum = require('bignum');

/**
 * @typedef {Object} KeyPair
 * @property {PaillierPublicKey} publicKey - a Paillier's public key
 * @property {PaillierPrivateKey} privateKey - the associated Paillier's private key
 */

/**
 * Generates a pair private, public key for the Paillier cryptosystem in synchronous mode
 * 
 * @param {number} bitLength - the bit lenght of the public modulo
 * @param {boolean} simplevariant - use the simple variant to compute the generator
 * 
 * @returns {KeyPair} - a pair of public, private keys
 */
const generateRandomKeys = function (bitLength = 4096, simplevariant = false) {
    let p, q, n, phi, n2, g, lambda, mu;
    // if p and q are bitLength/2 long ->  2**(bitLength - 2) <= n < 2**(bitLenght) 
    do {
        p = bignum.prime(bitLength / 2);
        q = bignum.prime(bitLength / 2);
        n = p.mul(q);
    } while (q.cmp(p) == 0 || n.bitLength() != bitLength);

    phi = p.sub(1).mul(q.sub(1));

    n2 = n.pow(2);

    if (simplevariant === true) {
        //If using p,q of equivalent length, a simpler variant of the key
        // generation steps would be to set
        // g=n+1, lambda=(p-1)(q-1), mu=lambda.invertm(n)
        g = n.add(1);
        lambda = phi;
        mu = lambda.invertm(n);
    } else {
        g = getGenerator(n, n2);
        lambda = lcm(p.sub(1), q.sub(1));
        mu = L(g.powm(lambda, n2), n).invertm(n);
    }

    const publicKey = new PaillierPublicKey(n, g);
    const privateKey = new PaillierPrivateKey(lambda, mu, p, q, publicKey);
    return { publicKey: publicKey, privateKey: privateKey };
};

/**
 * Generates a pair private, public key for the Paillier cryptosystem in asynchronous mode
 * 
 * @param {number} bitLength - the bit lenght of the public modulo
 * @param {boolean} simplevariant - use the simple variant to compute the generator
 * 
 * @returns {Promise} - a promise that returns a {@link KeyPair} if resolve
 */
const generateRandomKeysAsync = async function (bitLength = 4096, simplevariant = false) {
    return generateRandomKeys(bitLength, simplevariant);
};

/**
 * Class for a Paillier public key
 */
const PaillierPublicKey = class PaillierPublicKey {
    /**
    * Creates an instance of class PaillierPublicKey
    * @param {bignum | stringBase10 | number} n - the public modulo
    * @param {bignum | stringBase10 | number} g - the public generator
     */
    constructor(n, g) {
        this.n = bignum(n);
        this._n2 = this.n.pow(2); // cache n^2
        this.g = bignum(g);
    }

    /**
     * Get the bit length of the public modulo
     * @return {number} - bit length of the public modulo
     */
    get bitLength() {
        return this.n.bitLength();
    }

    /**
     * Paillier public-key encryption
     * 
     * @param {bignum | stringBase10 | number} m - a cleartext number
     * 
     * @returns {bignum} - the encryption of m with this public key
     */
    encrypt(m) {
        let r;
        do {
            r = bignum.rand(this.n);
        } while (r.le(1));
        return this.g.powm(bignum(m), this._n2).mul(r.powm(this.n, this._n2)).mod(this._n2);
    }

    /**
     * Homomorphic addition
     * 
     * @param {...bignums} - 2 or more (big) numbers (m_1,..., m_n) encrypted with this public key
     * 
     * @returns {bignum} - the encryption of (m_1 + ... + m_2) with this public key
     */
    addition(...ciphertexts) { // ciphertexts of numbers
        return ciphertexts.reduce((sum, next) => sum.mul(bignum(next)).mod(this._n2), bignum(1));
    }

    /**
     * Pseudo-homomorphic paillier multiplication
     * 
     * @param {bignum} c - a number m encrypted with this public key
     * @param {bignum | stringBase10 | number} k - either a cleartext message (number) or a scalar
     * 
     * @returns {bignum} - the ecnryption of k·m with this public key
     */
    multiply(c, k) { // c is ciphertext. k is either a cleartext message (number) or a scalar
        if (typeof k === 'string')
            k = bignum(k);
        return bignum(c).powm(k, this._n2);
    }
};

/**
 * Class for Paillier private keys.
 */
const PaillierPrivateKey = class PaillierPrivateKey {
    /**
     * Creates an instance of class PaillierPrivateKey
     * 
     * @param {bignum | stringBase10 | number} lambda 
     * @param {bignum | stringBase10 | number} mu 
     * @param {bignum | stringBase10 | number} p - a big prime
     * @param {bignum | stringBase10 | number} q - a big prime
     * @param {PaillierPublicKey} publicKey
     */
    constructor(lambda, mu, p, q, publicKey) {
        this.lambda = bignum(lambda);
        this.mu = bignum(mu);
        this._p = bignum(p);
        this._q = bignum(q);
        this.publicKey = publicKey;
    }

    /**
     * Get the bit length of the public modulo
     * @return {number} - bit length of the public modulo
     */
    get bitLength() {
        return this.publicKey.n.bitLength();
    }

    /**
     * Get the public modulo n=p·q
     * @returns {bignum} - the public modulo n=p·q
     */
    get n() {
        return this.publicKey.n;
    }

    /**
     * Paillier private-key decryption
     * 
     * @param {bignum | stringBase10} c - a (big) number encrypted with the public key
     * 
     * @returns {bignum} - the decryption of c with this private key
     */
    decrypt(c) {
        return L(bignum(c).powm(this.lambda, this.publicKey._n2), this.publicKey.n).mul(this.mu).mod(this.publicKey.n);
    }
};

function lcm(a, b) {
    return a.mul(b).div(a.gcd(b));
}

function L(a, n) {
    return a.sub(1).div(n);
}

function getGenerator(n, n2 = n.pow(2)) {
    const alpha = bignum.rand(n);
    const beta = bignum.rand(n);
    return alpha.mul(n).add(1).mul(beta.powm(n, n2)).mod(n2);
}

module.exports = {
    generateRandomKeys: generateRandomKeys,
    generateRandomKeysAsync: generateRandomKeysAsync,
    PrivateKey: PaillierPrivateKey,
    PublicKey: PaillierPublicKey
};