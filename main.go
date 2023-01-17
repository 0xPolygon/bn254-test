package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/kilic/bn254"
	"github.com/kilic/bn254/bls"

	bn256 "github.com/umbracle/go-eth-bn256"
)

func main() {
	msg, err := hex.DecodeString("fd7ead7342004b3a32ad")
	if err != nil {
		panic(err)
	}

	domain, err := hex.DecodeString("602611de35678287e7fce135407021b7a06afed4cfbbbec5fad0f0ad583e67a1")
	if err != nil {
		panic(err)
	}

	M, err := bn254.NewG1().HashToCurveFT(msg, domain)
	if err != nil {
		panic(err)
	}
	fmt.Println(M)

	res, err := hashToFpXMDSHA256(msg, domain, 2)
	if err != nil {
		panic(err)
	}

	g1 := new(bn256.G1)
	p0 := res[0]
	// ??
}

func main3() {
	g2B := mustDecodeBytes("234a5bd47557d86e76eb95d6e7d41f885f24fe450493bec98babd015728a114e18414e8b403c7e67cdd5b51d41952727d8a28de3734ee4a2114b8c282ce5643f22dd40a86c0efa6719c04ccaa78da913b89efe0c05916eaaa3ff1706367313702a1821de9d934b99c2bbf20bdf25ee9a98d6ef34c539f8880a06637eea2cbfa7")
	g1B := mustDecodeBytes("2583e262990c4ed1d68077cf180d4c3f71ee397d4ac1208f9aa0c114f31ee86e2f16020f0981a38d7d40d96b2dd3e0152a5003ff591e5a1526d0251a7ab56fcb")

	pointG2, err := bn254.NewG2().FromBytes(g2B)
	if err != nil {
		panic(err)
	}
	pointG1, err := bn254.NewG1().FromBytes(g1B)
	if err != nil {
		panic(err)
	}

	fmt.Println(pointG2)
	fmt.Println(pointG1)

	b2 := new(bn256.G2)
	if _, err := b2.Unmarshal(g2B); err != nil {
		panic(err)
	}
	b1 := new(bn256.G1)
	if _, err := b1.Unmarshal(g1B); err != nil {
		panic(err)
	}

	fmt.Println(b2)
	fmt.Println(b1)
}

func main2() {

	/*
		// Hash point - Works
		msg, err := hex.DecodeString("fd7ead7342004b3a32ad")
		if err != nil {
			panic(err)
		}

		domain, err := hex.DecodeString("602611de35678287e7fce135407021b7a06afed4cfbbbec5fad0f0ad583e67a1")
		if err != nil {
			panic(err)
		}
		res, err := bn254.ExpandMsgSHA256XMD(msg, domain, 96)
		if err != nil {
			panic(err)
		}
	*/

	/*
		// domain
		1262f59fb8516b07b14074faa5896ce6ac0c7301c798dbabc458e67d0f35ad5f
		// pub key
		[
		  '0x1995c03217bfbda50a5392033682dde996e48b6a51493f354dc41337e07ba3fd',
		  '0x0680ffe241e4295eb3670d7c003912b7c3e8359ce4c6abba9c0e8dcc0fb7131a',
		  '0x030f1d248b7389e4d803862d8a1b1907bcbf15b0162a9054c83d63e295dc33f7',
		  '0x1e8c304a8e7347d38015b74960c0f5d0bf5064555a5f0cf79ca0fee273fc328f'
		]
		// signature
		[
		  '0x1692824a2e76ce597dd918adc45a6f1bbb3c1b9d3f0839fde483b81da31c2362',
		  '0x0366f2eacb1eb15544d570eb16ffea90ba6e5a429f0459ed470ed8d21827ab24'
		]
		message
		abcd
	*/

	domain := mustDecodeBytes("508e30424791cb9a71683381558c3da1979b6fa423b2d6db1396b1d94d7c4a78")
	message := mustDecodeBytes("abcd")

	// in big endian format, this is tricky!
	pub, err := bls.PublicKeyFromBytes(mustDecodeBytes("234a5bd47557d86e76eb95d6e7d41f885f24fe450493bec98babd015728a114e18414e8b403c7e67cdd5b51d41952727d8a28de3734ee4a2114b8c282ce5643f22dd40a86c0efa6719c04ccaa78da913b89efe0c05916eaaa3ff1706367313702a1821de9d934b99c2bbf20bdf25ee9a98d6ef34c539f8880a06637eea2cbfa7"))
	if err != nil {
		panic(err)
	}
	sig, err := bls.SignatureFromBytes(mustDecodeBytes("2583e262990c4ed1d68077cf180d4c3f71ee397d4ac1208f9aa0c114f31ee86e2f16020f0981a38d7d40d96b2dd3e0152a5003ff591e5a1526d0251a7ab56fcb"))
	if err != nil {
		panic(err)
	}

	verifier := bls.NewBLSVerifier(domain)
	fmt.Println(verifier.Verify(message, sig, pub))
}

func mustDecodeBytes(str string) []byte {
	buf, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return buf
}

// ******

func hashToFpXMDSHA256(msg []byte, domain []byte, count int) ([]*big.Int, error) {
	randBytes, err := expandMsgSHA256XMD(msg, domain, count*48)
	if err != nil {
		return nil, err
	}
	els := make([]*big.Int, count)
	for i := 0; i < count; i++ {
		res := new(big.Int).SetBytes(randBytes[i*48 : (i+1)*48])
		if res == nil {
			return nil, fmt.Errorf("invalid big int")
		}
		els[i] = res
	}
	return els, nil
}

func expandMsgSHA256XMD(msg []byte, domain []byte, outLen int) ([]byte, error) {
	h := sha256.New()
	if len(domain) > 255 {
		return nil, errors.New("invalid domain length")
	}
	domainLen := uint8(len(domain))
	// DST_prime = DST || I2OSP(len(DST), 1)
	// b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
	_, _ = h.Write(make([]byte, h.BlockSize()))
	_, _ = h.Write(msg)
	_, _ = h.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b0 := h.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	_, _ = h.Write(b0)
	_, _ = h.Write([]byte{1})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b1 := h.Sum(nil)

	// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
	ell := (outLen + h.Size() - 1) / h.Size()
	bi := b1
	out := make([]byte, outLen)
	for i := 1; i < ell; i++ {
		h.Reset()
		// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		tmp := make([]byte, h.Size())
		for j := 0; j < h.Size(); j++ {
			tmp[j] = b0[j] ^ bi[j]
		}
		_, _ = h.Write(tmp)
		_, _ = h.Write([]byte{1 + uint8(i)})
		_, _ = h.Write(domain)
		_, _ = h.Write([]byte{domainLen})

		// b_1 || ... || b_(ell - 1)
		copy(out[(i-1)*h.Size():i*h.Size()], bi[:])
		bi = h.Sum(nil)
	}
	// b_ell
	copy(out[(ell-1)*h.Size():], bi[:])
	return out[:outLen], nil
}

func mulmod(x, y, N *big.Int) *big.Int {
	xx := new(big.Int).Mul(x, y)
	return xx.Mod(xx, N)
}

func addmod(x, y, N *big.Int) *big.Int {
	xx := new(big.Int).Add(x, y)
	return xx.Mod(xx, N)
}

func inversemod(x, N *big.Int) *big.Int {
	return new(big.Int).ModInverse(x, N)
}

/**
 * @notice returns square root of a uint256 value
 * @param xx the value to take the square root of
 * @return x the uint256 value of the root
 * @return hasRoot a bool indicating if there is a square root
 */
func sqrt(xx *big.Int) (x *big.Int, hasRoot bool) {
	x = new(big.Int).ModSqrt(xx, P)
	hasRoot = x != nil && mulmod(x, x, P).Cmp(xx) == 0
	return
}

//     // sqrt(-3)
//    // prettier-ignore
//    uint256 private constant Z0 = 0x0000000000000000b3c4d79d41a91759a9e4c7e359b6b89eaec68e62effffffd;
//    // (sqrt(-3) - 1)  / 2
//    // prettier-ignore
//    uint256 private constant Z1 = 0x000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe;

var Z0, _ = new(big.Int).SetString("0000000000000000b3c4d79d41a91759a9e4c7e359b6b89eaec68e62effffffd", 16)
var Z1, _ = new(big.Int).SetString("000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe", 16)

func bigFromBase10(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

// P is a prime over which we form a basic field: 36u⁴+36u³+24u²+6u+1.
var P = bigFromBase10("21888242871839275222246405745257275088696311157297823662689037894645226208583")

func mapToPoint(x *big.Int) (*big.Int, *big.Int) {

	_, decision := sqrt(x)

	// N := P

	//         uint256 a0 = mulmod(x, x, N);
	a0 := mulmod(x, x, P)
	//        a0 = addmod(a0, 4, N);
	a0 = addmod(a0, big.NewInt(4), P)
	//        uint256 a1 = mulmod(x, Z0, N);
	a1 := mulmod(x, Z0, P)
	//        uint256 a2 = mulmod(a1, a0, N);
	a2 := mulmod(a1, a0, P)
	//        a2 = inverse(a2);
	a2 = inversemod(a2, P)
	//        a1 = mulmod(a1, a1, N);
	a1 = mulmod(a1, a1, P)
	//        a1 = mulmod(a1, a2, N);
	a1 = mulmod(a1, a2, P)

	//         // x1
	//        a1 = mulmod(x, a1, N);
	a1 = mulmod(x, a1, P)
	//        x = addmod(Z1, N - a1, N);
	x = addmod(Z1, new(big.Int).Sub(P, a1), P)
	//        // check curve
	//        a1 = mulmod(x, x, N);
	a1 = mulmod(x, x, P)
	//        a1 = mulmod(a1, x, N);
	a1 = mulmod(a1, x, P)
	//        a1 = addmod(a1, 3, N);
	a1 = addmod(a1, big.NewInt(3), P)
	//        bool found;
	//        (a1, found) = sqrt(a1);
	var found bool
	//        if (found) {
	//            if (!decision) {
	//                a1 = N - a1;
	//            }
	//            return [x, a1];
	//        }
	if a1, found = sqrt(a1); found {
		if !decision {
			a1 = new(big.Int).Sub(P, a1)
		}
		return x, a1
	}

	//         // x2
	//        x = N - addmod(x, 1, N);
	x = new(big.Int).Sub(P, addmod(x, big.NewInt(1), P))
	//        // check curve
	//        a1 = mulmod(x, x, N);
	a1 = mulmod(x, x, P)
	//        a1 = mulmod(a1, x, N);
	a1 = mulmod(a1, x, P)
	//        a1 = addmod(a1, 3, N);
	a1 = addmod(a1, big.NewInt(3), P)
	//        (a1, found) = sqrt(a1);
	//        if (found) {
	//            if (!decision) {
	//                a1 = N - a1;
	//            }
	//            return [x, a1];
	//        }
	if a1, found = sqrt(a1); found {
		if !decision {
			a1 = new(big.Int).Sub(P, a1)
		}
		return x, a1
	}

	//         // x3
	//        x = mulmod(a0, a0, N);
	x = mulmod(a0, a0, P)
	//        x = mulmod(x, x, N);
	x = mulmod(x, x, P)
	//        x = mulmod(x, a2, N);
	x = mulmod(x, a2, P)
	//        x = mulmod(x, a2, N);
	x = mulmod(x, a2, P)
	//        x = addmod(x, 1, N);
	x = addmod(x, big.NewInt(1), P)

	//        // must be on curve
	//        a1 = mulmod(x, x, N);
	a1 = mulmod(x, x, P)

	//        a1 = mulmod(a1, x, N);
	a1 = mulmod(a1, x, P)

	//        a1 = addmod(a1, 3, N);
	a1 = addmod(a1, big.NewInt(3), P)

	//        (a1, found) = sqrt(a1);
	//        require(found, "BLS: bad ft mapping implementation");
	if a1, found = sqrt(a1); !found {
		panic("should not happen")
	}
	//        if (!decision) {
	//            a1 = N - a1;
	//        }
	//        return [x, a1];
	if !decision {
		a1 = new(big.Int).Sub(P, a1)
	}
	return x, a1
}
