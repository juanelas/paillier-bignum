'use strict';

const paillier = require('./paillier');
const bignum = require('bignum');

const {publicKey, privateKey} = paillier.generateRandomKeys(2048); // Change to at least 2048 bits in production state

console.log('modulus of', publicKey.n.bitLength(), 'bits');

console.log('\n\nTesting additive homomorphism\n');

const num1 = 10;
const num2 = 4;
const bn1 = bignum(num1).mod(publicKey.n);
let bn2 = bignum(num2).mod(publicKey.n);
while (bn2.lt(0)) bn2 = bn2.add(publicKey.n);  // bug in bignum? mod of negative keeps being negative. This should fix it

const c1 = publicKey.encrypt(bn1);
const c2 = publicKey.encrypt(bn2);

console.log('num1:', num1.toString());
console.log('c1:', c1.toString(16), '\n');

console.log('num2:', num2.toString());
console.log('c2:', c2.toString(16), '\n');

const encryptedSum = c1.mul(c2).mod(publicKey._n2);
console.log('c1*c2:', encryptedSum.toString(16), '\n');

const sum = privateKey.decrypt(encryptedSum);
console.log('Decryption of c1*c2:', sum.toString());
console.log('num1+num2=', num1 + num2, '\n\n');

const pubKey = new paillier.PublicKey(publicKey.n, publicKey.g);
const privKey = new paillier.PrivateKey(privateKey.lambda, privateKey.mu, privateKey.p, privateKey.q, pubKey);

const num3 = bignum(4);
const c3 = pubKey.encrypt(num3);
console.log(privKey.decrypt(c3).toString());