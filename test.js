'use strict';

const paillier = require('./paillier');
const bignum = require('bignum');

const keys = paillier.generateKeys(1024); // Change to at least 2048 bits in production state

console.log('modulus:', keys.publicKey.n.bitLength());
console.log(keys);

console.log('\n\nTesting additive homomorphism\n');

const num1 = 10;
const num2 = -5;
const bn1 = bignum(num1).mod(keys.publicKey.n);
let bn2 = bignum(num2).mod(keys.publicKey.n);
while (bn2.lt(0)) bn2 = bn2.add(keys.publicKey.n);  // bug in bignum? mod of negative keeps being negative. This should fix it

const c1 = keys.publicKey.encrypt(bn1);
const c2 = keys.publicKey.encrypt(bn2);

console.log('num1:', num1.toString());
console.log('c1:', c1.toString(16));

console.log('num2:', num2.toString());
console.log('c2:', c2.toString(16), '\n');

const encryptedSum = c1.mul(c2).mod(keys.publicKey.n2);
console.log('c1*c2:', encryptedSum.toString(16), '\n');

const sum = keys.privateKey.decrypt(encryptedSum);
console.log('Decryption of c1*c2:', sum.toString());
console.log('num1+num2=', num1 + num2, '\n\n');
