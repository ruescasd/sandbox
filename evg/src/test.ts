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

import { arithm, crypto, util, eio } from "./vjsc-1.1.1.js"
import { inspect } from "util"

console.log("****************** test.js ******************")

/////////////////////// Randomness ///////////////////////

let randomSource = new crypto.RandomDevice()
let statDist = 50

/////////////////////// Obtaining groups, generator, LI ///////////////////////

let groupName = "modp768"

let params = arithm.ModPGroup.getParams(groupName)
// console.log(params)
// console.log(arithm.ModPGroup.getPGroupNames())
let group: arithm.ModPGroup = arithm.ModPGroup.getPGroup(groupName)

let gString: string = arithm.ModPGroup.getParams(groupName)[1]
let generatorLI: arithm.LargeInteger = new arithm.LargeInteger(gString)

let g1: arithm.ModPGroupElement = group.getg()
let order: arithm.LargeInteger = group.getElementOrder()
console.log(g1.exp(order).equals(group.getONE()))

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
    
    // let s = group.pRing.randomElement(randomSource, statDist)
    // let d = group.getg().exp(s)

    // let b = pPGroup.prod([c, d])

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

const spo = new crypto.SigmaProofOr(group.pRing, sps)
proof = spo.prove(label, instances, [witnesses[correct], correct],
    crypto.sha256, randomSource, 50)
console.log("CDS")
ok = spo.verify(label, instances, crypto.sha256, proof)
console.log("=====================")
console.log(ok)
let badWitness = eh.domain.randomElement(randomSource, statDist) 
let invalidProof = spo.prove(label, instances, [badWitness, correct],
    crypto.sha256, randomSource, 50)
ok = spo.verify(label, instances, crypto.sha256, invalidProof)
console.log(!ok)

/////////////////////// Threshold Cryptosystem ///////////////////////

let n = 5
let k = 3

class Trustee {
    numTrustees: number
    threshold: number
    coefficients: arithm.PRingElement[] = []
    commitments: arithm.ModPGroupElement[] = []
    shares: arithm.PRingElement[] = []
    externalShares: arithm.PRingElement[] = []

    // A degree n polynomial is uniquely determined by n + 1 points
    // Therefore necessary threshold = n + 1, so degree = threshold - 1
    // Therefore number of coefficients = threshold (degree n has n + 1 coefficients)
    constructor(numTrustees: number, threshold: number) {
        this.numTrustees = numTrustees
        this.threshold = threshold

        for (let i = 0; i < threshold; i++) {
            this.coefficients[i] = group.pRing.randomElement(randomSource, statDist)
            this.commitments[i] =  group.getg().exp(this.coefficients[i])
        }
        for (let i = 0; i < numTrustees; i++) {
            this.shares[i] = this.evalPoly(i + 1)
        }
    }
    private evalPoly(trustee: number): arithm.PRingElement {
        let sum = this.coefficients[0]
        let trusteeInt = new arithm.LargeInteger(trustee.toString())
        let power = group.pRing.getONE()
        
        for (let i = 1; i < this.threshold; i++) {
            power = power.mul(trusteeInt)
            sum = sum.add(this.coefficients[i].mul(power))
        }

        return sum
    }

    static lagrange(trustee: number, present: number[]): arithm.PRingElement {
        let numerator = group.pRing.getONE()
        let denominator = group.pRing.getONE()
        let trusteeInt = new arithm.LargeInteger(trustee.toString())

        for(let i = 0; i < present.length; i++) {
            if(present[i] == trustee)    continue
            let presentInt = new arithm.LargeInteger(present[i].toString())
            let diffInt = new arithm.LargeInteger((present[i] - trustee).toString())
            numerator = numerator.mul(presentInt)
            denominator = denominator.mul(diffInt)
        }

        return numerator.mul(denominator.inv())
    }
}

let trustees: Trustee[] = []
let pk: arithm.ModPGroupElement = group.getONE()
for (let i = 0; i < n; i++) {
    trustees[i] = new Trustee(n, k)
    pk = pk.mul(trustees[i].commitments[0])
}
for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
        if(i == j)  continue
        trustees[j].externalShares[i] = trustees[i].shares[j]
    }
}

let pkGroup = new arithm.PPGroup([group, group]);
let publicKey = pkGroup.prod([group.getg(), pk]);

let messageString = "Hello World"
let messageBytes: Uint8Array = util.asciiToByteArray(messageString)
let message: arithm.ModPGroupElement = group.encode(messageBytes, 0, messageBytes.length)
let elgamal: crypto.ElGamal = new crypto.ElGamal(true, group, randomSource, statDist)
let encrypted: arithm.PPGroupElement = elgamal.encrypt(publicKey, message)

// all trustees present

let alpha: arithm.ModPGroupElement = encrypted.project(0)
let beta: arithm.ModPGroupElement = encrypted.project(1)
let divider: arithm.ModPGroupElement = group.getONE()
for (let i = 0; i < n; i++) {
    divider = divider.mul(alpha.exp(trustees[i].coefficients[0]))
}
let decryption: arithm.ModPGroupElement = beta.mul(divider.inv())
let decryptedBytes = new Uint8Array(messageBytes.length)
decryption.decode(decryptedBytes, 0)

let decryptedString = util.byteArrayToAscii(decryptedBytes) 
console.log(messageString == decryptedString)

// threshold decryption

let present = [1, 4, 5]
let missing = [2, 3]

let dividers: arithm.ModPGroupElement[] = util.fill(group.getONE(), n)
let lagranges: arithm.PRingElement[] = new Array<arithm.PRingElement>(n)

for(let i = 0; i < present.length; i++) {
    dividers[present[i] - 1] = alpha.exp(trustees[present[i] - 1].coefficients[0])
    lagranges[present[i] - 1] = Trustee.lagrange(present[i], present)
}

for(let j = 0; j < missing.length; j++) {
    
    for(let i = 0; i < present.length; i++) {
        let nextShare = trustees[present[i] - 1].externalShares[missing[j] - 1]
        dividers[missing[j] - 1] = dividers[missing[j] - 1].mul(
            alpha.exp(nextShare).exp(lagranges[present[i] - 1])
        )   
    }
}

divider = group.getONE()
for(let i = 0; i < n; i++) {
    divider = divider.mul(dividers[i])
}

decryption = beta.mul(divider.inv())
decryptedBytes = new Uint8Array(messageBytes.length)
decryption.decode(decryptedBytes, 0)

decryptedString = util.byteArrayToAscii(decryptedBytes) 
console.log(messageString == decryptedString)



