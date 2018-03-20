'use strict';

const bignum = require('bignum');

const generateRandomKeys = function (bitLength = 2048, simplevariant = false) {
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

const PaillierPublicKey = class PaillierPublicKey {
    constructor(n, g) {
        this.n = bignum(n);
        this._n2 = n.pow(2); // cache n^2
        this.g = bignum(g);
    }
    get bitLength() {
        return this.n.bitLength();
    }
    encrypt(m) {
        let r;
        do {
            r = bignum.rand(this.n);
        } while (r.le(1));
        return this.g.powm(bignum(m), this._n2).mul(r.powm(this.n, this._n2)).mod(this._n2);
    }
    addition(...numbers) { // numbers must be ciphertexts
        return numbers.reduce((sum, next) => sum.mul(bignum(next)).mod(this._n2), bignum(1));
    }
    multiply(c, k) { // c is ciphertext. m is a number in plain text
        return bignum(c).powm(k, this._n2);
    }
};

const PaillierPrivateKey = class PaillierPrivateKey {
    constructor(lambda, mu, p, q, publicKey) {
        this.lambda = bignum(lambda);
        this.mu = bignum(mu);
        this._p = bignum(p);
        this._q = bignum(q);
        this.publicKey = publicKey;
    }
    get bitLength() {
        return this.publicKey.n.bitLength();
    }
    get n() {
        return this.publicKey.n;
    }
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
    PrivateKey: PaillierPrivateKey,
    PublicKey: PaillierPublicKey
};