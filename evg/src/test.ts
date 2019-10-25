/* Questions for Douglas 

* Why does ModPGroup random element do this:

var bits = 8 * this.modulusByteLength + statDist;
var r = new LargeInteger(bits, randomSource);
return new ModPGroupElement(this, r.mod(this.modulus));

This does not take into account the order of the group, seems to generate
a random element over the entire group (even though safeprime is the default if not specified)

* The readme description of PGroup and ModPGroup does not match the comments for those classes,
re prime order and subgroup.

*/

import { arithm, crypto, util } from "./vjsc-1.1.1.js"

/////////////////////// Obtaining groups, generator, LI ///////////////////////

let groupName = "modp2048"

let params = arithm.ModPGroup.getParams(groupName)
// console.log(params)
// console.log(arithm.ModPGroup.getPGroupNames())
let group: arithm.ModPGroup = arithm.ModPGroup.getPGroup(groupName)

let gString: string = arithm.ModPGroup.getParams(groupName)[1]
let generatorLI: arithm.LargeInteger = new arithm.LargeInteger(gString)

let g1: arithm.ModPGroupElement = group.getg()
let order: arithm.LargeInteger = group.getElementOrder()
console.log(g1.exp(order).equals(group.getONE()))

/////////////////////// Randomness ///////////////////////

let randomSource = new crypto.RandomDevice()
let statDist = 50

/////////////////////// Byte arrays in typescript ///////////////////////

let bytes: Uint8Array = randomSource.getBytes(20)

/////////////////////// Hashing ///////////////////////

let result = crypto.sha256.hash(bytes)

/////////////////////// Schnorr (as generalized SigmaProof) ///////////////////////

let eh = new arithm.ExpHom(group.pRing, group.getg())
let sp = new crypto.SchnorrProof(eh)
let witness: arithm.PRingElement = eh.domain.randomElement(randomSource, statDist)
let instance: arithm.ModPGroupElement = eh.eva(witness)

let label = randomSource.getBytes(10)
let proof = sp.prove(label, instance, witness, crypto.sha256, randomSource, 50)
let ok = sp.verify(label, instance, crypto.sha256, proof)
console.log(ok)

/////////////////////// Chaum-Pedersen (as generalized SigmaProof using Schnorr class) ///////////////////////

let pPGroup = new arithm.PPGroup([group, group])
let t = group.pRing.randomElement(randomSource, statDist)
var c = group.getg().exp(t)

let s = group.pRing.randomElement(randomSource, statDist)
let d = group.getg().exp(s)

let b = pPGroup.prod([c, d])

// eh(x) = (c^x, d^x)
eh = new arithm.ExpHom(group.pRing, b)
sp = new crypto.SchnorrProof(eh)
witness = eh.domain.randomElement(randomSource, statDist)
instance = eh.eva(witness)
proof = sp.prove(label, instance, witness, crypto.sha256, randomSource, 50)
ok = sp.verify(label, instance, crypto.sha256, proof)

console.log(ok)

/////////////////////// Chaum-Pedersen + Cramer-Damgard-Schoenmakers ///////////////////////
// TODO: check with Douglas

let sps: crypto.SchnorrProof[] = []
let witnesses: arithm.PRingElement[] = []
let instances: arithm.PGroupElement[] = []

let correct = 0
for (let j = 0; j < 2; j++) {
    
    let s = group.pRing.randomElement(randomSource, statDist)
    let d = group.getg().exp(s)

    let b = pPGroup.prod([c, d])

    // eh(x) = (c^x, d^x)
    eh = new arithm.ExpHom(group.pRing, b)
    sps[j] = new crypto.SchnorrProof(eh)
    witnesses[j] =
            eh.domain.randomElement(randomSource, statDist)
    if(j == correct) {
        instances[j] = eh.eva(witnesses[j])
    }
    else {
        let fake = eh.domain.randomElement(randomSource, statDist)
        instances[j] = eh.eva(fake)
    }
}

sp = new crypto.SigmaProofOr(group.pRing, sps)
proof = sp.prove(label, instances, [witnesses[correct], correct],
    crypto.sha256, randomSource, 50)
ok = sp.verify(label, instances, crypto.sha256, proof)
console.log(ok)
let badWitness = eh.domain.randomElement(randomSource, statDist) 
let invalidProof = sp.prove(label, instances, [badWitness, correct],
    crypto.sha256, randomSource, 50)
ok = sp.verify(label, instances, crypto.sha256, invalidProof)
console.log(!ok)

/////////////////////// Threshold Cryptosystem ///////////////////////

let n = 5
let k = 3

class Trustee {
    coefficients: arithm.PRingElement[] = []
    externalShares: arithm.PRingElement[] = []
    numTrustees: number
    threshold: number
    shares: arithm.PRingElement[] = []
    commitments: arithm.ModPGroupElement[] = []
    // a degree n polynomial is uniquely determined by n + 1 points
    // Therefore threshold = n + 1 => degree = threshold - 1
    // Therefore number of coefficients = threshold (degree n has n + 1 coefficients)
    constructor(numTrustees: number, threshold: number) {
        this.numTrustees = numTrustees
        this.threshold = threshold
    }
}