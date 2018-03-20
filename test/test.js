var expect = require('chai').expect;
var paillier = require('../paillier');
var bignum = require('bignum');

const bitLength = 1024;
let publicKey, privateKey;

describe(`generateRandomKeys(${bitLength})`, function () {
    ({ publicKey, privateKey } = paillier.generateRandomKeys(bitLength));
    it('should return publicKey and privateKey', function () {
        expect(publicKey).to.be.an.instanceOf(paillier.PublicKey);
        expect(privateKey).to.be.an.instanceOf(paillier.PrivateKey);
    });
    it(`should return a public modulus of ${bitLength}`, function () {
        expect(publicKey.bitLength).to.equal(bitLength);
    });
});

const length = 45;
const numbers = new Array(length);
for (let i = 0; i < length; i++) {
    numbers[i] = bignum.rand(publicKey.n);
}
const ciphertexts = new Array(length);
numbers.forEach(function(item, index) {
    ciphertexts[index] = publicKey.encrypt(item);
});
const sumNumbers = numbers.reduce((sum, next) => sum.add(next).mod(publicKey.n));

describe('Encrypt m1 with publicKey and then decrypt with privateKey: D( E(m1) )', function () {
    let d = privateKey.decrypt(ciphertexts[0]);
    it('should return m1', function () {
        expect(d.cmp(numbers[0])).equals(0);
    });
});

describe(`Testing homomorphic addition of ${length} random numbers: D( E(m1, m2, ..., m${length}) )`, function () {
    const encSum = publicKey.addition(...ciphertexts);
    let d = privateKey.decrypt(encSum);
    it(`should return m1+m2+...+m${length}`, function () {
        expect(d.cmp(sumNumbers)).equals(0);
    });
});

describe('Testing (pseudo-)homomorphic multiplication: D( E(m1)^m1 )', function () {
    const encMul = publicKey.multiply(ciphertexts[0], numbers[0]);
    let d = privateKey.decrypt(encMul);
    it('should return the square of m1', function () {
        expect(d.cmp(numbers[0].powm(2, publicKey.n))).equals(0);
    });
});