'use strict';

const bignum = require('bignum');

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

const paillier = {
    _publicKey: function (bits, n, g) {
        // bits
        this.bits = bits;
        // n
        this.n = n;
        // n2 (cached n^2)
        this.n2 = n.pow(2);
        this.g = g;
    },
    _privateKey: function (lambda, mu, p, q, publicKey) {
        this.lambda = lambda;
        this.mu = mu;
        this.p = p;
        this.q = q;
        this.publicKey = publicKey;
    },
    getPublicKey: function (bits, n, g, format) {
        this.bits = bits;
        switch (format) {
        case 'dec':
            this.n = bignum(n);
            this.g = bignum(g);
            break;
        case 'hex':
            this.n = bignum(n, 16);
            this.g = bignum(g, 16);
            break;
        case 'base64':
            this.n = bignum.fromBuffer(new Buffer(n, 'base64'));
            this.g = bignum.fromBuffer(new Buffer(g, 'base64'));
            break;
        case 'bignum':
            this.n = n;
            this.g = g;
            break;
        default: // Big-endian binary Buffer
            this.n = bignum.fromBuffer(n);
            this.g = bignum.fromBuffer(g);
        }
        return new paillier._publicKey(this.bits, this.n, this.g);
    },
    getPrivateKey: function (lambda, mu, p, q, publicKey, format) {
        switch (format) {
        case 'dec':
            this.lambda = bignum(lambda);
            this.mu = bignum(mu);
            this.p = bignum(p);
            this.q = bignum(q);
            break;
        case 'hex':
            this.lambda = bignum(lambda, 16);
            this.mu = bignum(mu, 16);
            this.p = bignum(p, 16);
            this.q = bignum(q, 16);
            break;
        case 'base64':
            this.lambda = bignum.fromBuffer(new Buffer(lambda, 'base64'));
            this.mu = bignum.fromBuffer(new Buffer(mu, 'base64'));
            this.p = bignum.fromBuffer(new Buffer(p, 'base64'));
            this.q = bignum.fromBuffer(new Buffer(q, 'base64'));
            break;
        case 'bignum':
            this.lambda = lambda;
            this.mu = mu;
            this.p = p;
            this.q = q;
            break;
        default: // Big-endian binary Buffer
            this.lambda = bignum.fromBuffer(lambda);
            this.mu = bignum.fromBuffer(mu);
            this.p = bignum.fromBuffer(p);
            this.q = bignum.fromBuffer(q);
        }
        this.publicKey = publicKey;
        return new paillier._privateKey(this.lambda, this.mu, this.p, this.q, this.publicKey);
    },
    generateKeys: function (bitlength=2048, simplevariant) {
        let p, q, n, phi, n2, g, lambda, mu, keys = {};
        // if p and q are bitlength/2 long, n is then bitlength long
        this.bitlength = bitlength;
        console.log('Generating Paillier keys of', this.bitlength, 'bits');
        do {
            p = bignum.prime(this.bitlength / 2);
            q = bignum.prime(this.bitlength / 2);
            n = p.mul(q);
            phi = p.sub(1).mul(q.sub(1));
        } while (q.cmp(p) == 0 || n.bitLength() != this.bitlength);

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

        keys.publicKey = new paillier._publicKey(this.bitlength, n, g);
        keys.privateKey = new paillier._privateKey(lambda, mu, p, q, keys.publicKey);
        return keys;
    }
};

paillier._publicKey.prototype = {
    encrypt: function (m) {
        var r;
        do {
            r = bignum.rand(this.n);
        } while (r <= 1);
        return this.g.powm(m, this.n2).mul(r.powm(this.n, this.n2)).mod(this.n2);
    }
};

paillier._privateKey.prototype = {
    decrypt: function (c) {
        return L(c.powm(this.lambda, this.publicKey.n2), this.publicKey.n).mul(this.mu).mod(this.publicKey.n);
    },
};

module.exports = paillier;
