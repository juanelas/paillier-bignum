'use strict';

var expect = require('chai').expect;
var paillier = require('../src/paillier');

const bitLengths = [4096, 3072, 1024];
const timeout = 180000;

describe('Testing synchronous generation of Paillier keys', () => {
    for (const bitLength of bitLengths) {
        describe(`generateRandomKeys(${bitLength}) - timeout=${timeout / 1000} seg.`, () => {
            it(`should return a publicKey and a privateKey with public modulus of ${bitLength} bits`, function () {
                this.timeout(timeout);
                const keys = paillier.generateRandomKeys(bitLength);
                expect(keys.publicKey).to.be.an.instanceOf(paillier.PublicKey);
                expect(keys.privateKey).to.be.an.instanceOf(paillier.PrivateKey);
                expect(keys.publicKey.bitLength).to.equal(bitLength);
            });
        });
    }
});

describe('Testing asynchronous generation of Paillier keys. You are your source of randomness. Please move your mouse and/or execute basic commands to speed up the tests.', () => {
    for (const bitLength of bitLengths) {
        describe(`generateRandomKeysAsync(${bitLength}) - timeout=${timeout / 1000} seg.`, () => {
            it(`should return a publicKey and a privateKey with public modulus of ${bitLength} bits`, async function () {
                this.timeout(timeout);
                const keys = await paillier.generateRandomKeysAsync(bitLength);
                expect(keys.publicKey).to.be.an.instanceOf(paillier.PublicKey);
                expect(keys.privateKey).to.be.an.instanceOf(paillier.PrivateKey);
                expect(keys.publicKey.bitLength).to.equal(bitLength);
            });
        });
    }
});