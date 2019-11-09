export declare namespace arithm {    
    class ArithmObject {
        constructor()
        
        getName(): string
    }
    namespace sli {
        class SLI extends ArithmObject {
            constructor(first: any, second: any)    
        }
    }
    
    class LargeInteger extends sli.SLI {
        static ONE: LargeInteger
        
        constructor(first: any, second?: any)

        mul(other: LargeInteger): LargeInteger 
        add(other: LargeInteger): LargeInteger
        sub(other: LargeInteger): LargeInteger
        div(other: LargeInteger): LargeInteger

        toByteArray(): Uint8Array
        toByteArrayAlt(): Uint8Array
    }

    class PRing extends ArithmObject{
        constructor()

        randomElement(randomSource: crypto.RandomSource, statDist: number): PRingElement
        getPField(): PField
        getONE(): PRingElement
        toElement(byteTree: eio.ByteTree | Uint8Array): PRingElement
    }

    class PField extends PRing {
        constructor(order: number | LargeInteger)
        getPField(): PField
    }

    class PRingElement extends ArithmObject {
        constructor(pRing: PRing)
        
        equals(other: PRingElement): boolean
        neg(): PRingElement
        mul(other: PRingElement | LargeInteger): PRingElement
        add(other: PRingElement | LargeInteger): PRingElement
        sub(other: PRingElement | LargeInteger): PRingElement
        inv(): PRingElement
    }

    class PFieldElement extends PRingElement {
        constructor(pField: PField, value: LargeInteger)
    }

    class PGroup extends ArithmObject {
        constructor(pRing: any)
        pRing: PRing
        
        getONE(): PGroupElement
        getg(): PGroupElement
        getElementOrder(): LargeInteger
        getEncodeLength(): number
        toElement(byteTree: eio.ByteTree | Uint8Array): PGroupElement
        // when PPGroup, we need a bytetree to pass in
        toElementAlt(byteTree: eio.ByteTree): PGroupElement
    }
    
    class PGroupElement extends ArithmObject {
        constructor(pGroup: PGroup)
        equals(other: PGroupElement): boolean
        mul(factor: ModPGroupElement): ModPGroupElement
        fixed(exponentiations: number): void
        exp(exponent: LargeInteger | PRingElement): ModPGroupElement
        inv(): ModPGroupElement
        decode(destination: Uint8Array, startIndex: number): number
        toByteTree(): eio.ByteTree
        toByteTreeNoZero(): eio.ByteTree
    }
    
    class PPGroup extends PGroup {
        constructor(value: PGroup[], width?: number)

        prod(value: PGroupElement[]): PPGroupElement
    }

    class PPGroupElement extends PGroupElement {
        constructor(pPGroup: PPGroup, values: LargeInteger[])
        project(i: number): PGroupElement
    }
    
    class ModPGroup extends PGroup {
        static getPGroupNames(): string[]
        static getPGroup(groupName: string): ModPGroup
        static getParams (groupName: string): string[]
        
        constructor(modulus: any, order: any, gi: any, encoding: any)
        
        getONE(): ModPGroupElement
        getg(): ModPGroupElement
        getElementOrder(): LargeInteger
        encode(bytes: Uint8Array, startIndex: number, length: number): ModPGroupElement
        // toElement(byteTree: eio.ByteTree): ModPGroupElement
        toElement(byteTree: eio.ByteTree | Uint8Array): ModPGroupElement
    }
    
    class ModPGroupElement extends PGroupElement {
        equals(other: ModPGroupElement): boolean
        mul(factor: ModPGroupElement): ModPGroupElement
        fixed(exponentiations: number): void
        exp(exponent: LargeInteger | PRingElement): ModPGroupElement
        inv(): ModPGroupElement
    }

    class Hom {
        constructor(domain: ArithmObject, range: ArithmObject)
        eva(value: ArithmObject): ArithmObject
    }
    class ExpHom extends Hom {
        domain: PRing
        range: PGroup

        constructor(domain: PRing, basis: PGroupElement)
        eva(value: PRingElement): PGroupElement
    }
}

export declare namespace crypto {
    class RandomSource {
        constructor()
        getBytes(length: number): Uint8Array
    }

    class RandomDevice extends RandomSource {
        constructor()
        getBytes(length: number): Uint8Array
    }

    class ZKPoK {
        constructor()
        
        prove(label: Uint8Array, instance: any, witness: any, 
            hashfunction: HashFunction, randomSource: RandomSource, 
            statDist: number): Uint8Array
   
   
        verify(label: Uint8Array, instance: any, hashfunction: HashFunction, 
            proof: Uint8Array): boolean
    }
    
    class SigmaProof extends ZKPoK {
        constructor()

        instanceToByteTree(instance: arithm.PGroupElement | arithm.PGroupElement[]): eio.ByteTree
        byteTreeToCommitment(byteTree: eio.ByteTree): arithm.PGroupElement
        byteTreeToReply(byteTree: eio.ByteTree): arithm.PRingElement
        challenge(first: eio.ByteTree, second: crypto.HashFunction): arithm.PRingElement
    }

    class SigmaProofPara extends SigmaProof {
        sigmaProofs: SigmaProof[]
        
        constructor(sigmaProofs: SigmaProof[])
    }

    class SigmaProofOr extends SigmaProofPara {
        constructor(challengeSpace: arithm.PRing, param: SigmaProof[], copies?: number)
    }
    
    class SchnorrProof extends SigmaProof {
        homomorphism: arithm.ExpHom

        constructor(homomorphism: arithm.Hom)
    }

    interface HashFunction {
        hash(bytes: Uint8Array): Uint8Array
    }
    
    let sha256: HashFunction

    class ElGamal {
        constructor(standard: boolean, pGroup: arithm.PGroup, 
            randomSource: RandomSource, statDist: number)

            encrypt(publicKey: arithm.ModPGroupElement, message: arithm.ModPGroupElement, 
                random?: arithm.PRingElement): arithm.PPGroupElement
    }
}

export declare namespace util {
    function asciiToByteArray(ascii: string): Uint8Array
    function byteArrayToAscii(bytes: Uint8Array): string
    function hexToByteArray(hex: string): Uint8Array
    function byteArrayToHex(bytes: Uint8Array): string
    function fill<T>(value: T, width: number): Array<T>
    function equalsArray(a: Uint8Array, b: Uint8Array): boolean
}

export declare namespace eio {
    class ByteTree {
        static asByteTree(value: ByteTree | Uint8Array): ByteTree
        
        constructor(value: Uint8Array | ByteTree[] | string)

        isLeaf(): boolean
        toByteArray(): Uint8Array
        toByteArrayRaw(): Uint8Array
        toPrettyString(): string
    }
}
