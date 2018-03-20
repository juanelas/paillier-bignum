'use strict';
const paillier = require('./paillier');
const bignum = require('bignum');

let { publicKey, privateKey } = paillier.generateRandomKeys(512); // Change to at least 2048 bits in production state

console.log('Modulus n has', publicKey.n.bitLength(), 'bits');

console.log('\n\nTesting additive homomorphism\n');

const num1 = 5;
const num2 = 2;
let bn1 = bignum(num1).mod(publicKey.n);
while (bn1.lt(0)) bn1 = bn1.add(publicKey.n);  // bug in bignum? mod(n) of negative number returns .abs().mod(n). This should fix it
let bn2 = bignum(num2).mod(publicKey.n);
while (bn2.lt(0)) bn2 = bn2.add(publicKey.n);  // bug in bignum? mod(n) of negative number returns .abs().mod(n). This should fix it

const c1 = publicKey.encrypt(bn1);
const c2 = publicKey.encrypt(bn2);

console.log('num1:', num1.toString());
console.log('c1:', c1.toString(16), '\n');

console.log('num2:', num2.toString());
console.log('c2:', c2.toString(16), '\n');

const encryptedSum = publicKey.addition(c1, c2);
console.log('E(m1 + m2):', encryptedSum.toString(16), '\n');

const sum = privateKey.decrypt(encryptedSum);
console.log('Decryption:', sum.toString());
console.log(`Expecting ${num1} + ${num2} mod n :`, bn1.add(bn2).mod(publicKey.n).toString());

console.log('\n\nTesting multiplication\n');

const encryptedMul = publicKey.multiply(c1, bn2);
console.log(`E(${num1})^${num2} mod n^2 = E(${num2}·${num1} mod n) = ` + encryptedMul.toString(16), '\n');

const mul = privateKey.decrypt(encryptedMul);
console.log('Decryption:', mul.toString());
console.log(`Expecting ${num2}·${num1} mod n :`, bn2.mul(bn1).mod(publicKey.n).toString());