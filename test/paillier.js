'use strict'

// For the browser test builder to work you MUST import them module in a variable that
// is the camelised version of the package name.
const paillier = require('../paillier')
const chai = require('chai')

const bitLengths = [1024, 2048, 3072]
for (const bitLength of bitLengths) {
  describe(`Testing Paillier with keys of ${bitLength} bits`, function () {
    let keyPair
    const tests = 32
    const numbers = []
    const ciphertexts = []

    describe(`generateRandomKeys(${bitLength})`, function () {
      it(`it should return a publicKey and a privateKey with public modulus of ${bitLength} bits`, function () {
        keyPair = paillier.generateRandomKeys(bitLength)
        chai.expect(keyPair.publicKey).to.be.an.instanceOf(paillier.PublicKey)
        chai.expect(keyPair.privateKey).to.be.an.instanceOf(paillier.PrivateKey)
        chai.expect(keyPair.publicKey.bitLength).to.equal(bitLength)
      })
    })

    describe(`Correctness. For ${tests} random r in (1,n), encrypt r with publicKey and then decrypt with privateKey: D(E(r))`, function () {
      it('all should return r', function () {
        let testPassed = true
        for (let i = 0; i < tests; i++) {
          numbers[i] = keyPair.publicKey.n.rand()
          ciphertexts[i] = keyPair.publicKey.encrypt(numbers[i])
          const decrypted = keyPair.privateKey.decrypt(ciphertexts[i])
          if (numbers[i].cmp(decrypted) !== 0) {
            testPassed = false
            break
          }
        }
        chai.expect(testPassed).equals(true)
      })
    })

    describe('Homomorphic properties', function () {
      describe(`Homomorphic addition: D( E(m1)·...·E(m${tests})) mod n^2 )`, function () {
        it(`should return m1+...+m${tests} mod n`, function () {
          const encSum = keyPair.publicKey.addition(...ciphertexts)
          const d = keyPair.privateKey.decrypt(encSum)
          const sumNumbers = numbers.reduce((sum, next) => (sum.add(next)).mod(keyPair.publicKey.n))
          chai.expect(d.cmp(sumNumbers)).to.be.equal(0)
        })
      })
      describe(`For all the ${tests} random r, the (pseudo-)homomorphic multiplication: D( E(r)^r mod n^2 )`, function () {
        it('should return r^2 mod n', function () {
          let testPassed = true
          for (let i = 0; i < numbers.length; i++) {
            const encMul = keyPair.publicKey.multiply(ciphertexts[i], numbers[i])
            const d = keyPair.privateKey.decrypt(encMul)
            if (d.cmp(numbers[i].powm(2, keyPair.publicKey.n)) !== 0) {
              testPassed = false
              break
            }
          }
          chai.expect(testPassed).equals(true)
        })
      })
    })
  })
}
