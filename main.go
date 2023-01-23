package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	gbn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"

	"embed"

	"github.com/kilic/bn254"
	"github.com/kilic/bn254/bls"

	bn256 "github.com/umbracle/go-eth-bn256"
)

var testvectorDomain = mustDecodeBytes("3095095f89fc00bccc880012951f9530793473ec5142e85a5586203cd6d8512d")

//go:embed testvectors/*
var testvectors embed.FS

func decodeTestVector(name string, obj interface{}) {
	data, err := testvectors.ReadFile(name)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(data, obj); err != nil {
		panic(err)
	}
}

func main() {

	/*
		priv := &PrivateKey{
			s: new(big.Int).SetUint64(10),
		}

		pub := priv.PublicKey()

		buf, _ := pub.Marshal()
		fmt.Println(hex.EncodeToString(buf))

		for _, i := range pub.ToBigInt() {
			fmt.Println(hex.EncodeToString(i.Bytes()))
		}
	*/

	// aggregate

	{
		domain := mustDecodeBytes("508e30424791cb9a71683381558c3da1979b6fa423b2d6db1396b1d94d7c4a78")
		message := mustDecodeBytes("abcd")

		pubs := []*PublicKey{}
		sigs := []*Signature{}

		for i := 0; i < 5; i++ {
			priv, err := GenerateBlsKey()
			if err != nil {
				panic(err)
			}

			sign, err := priv.Sign(message, domain)
			if err != nil {
				panic(err)
			}

			pubs = append(pubs, priv.PublicKey())
			sigs = append(sigs, sign)
		}

		sig := aggregateSignatures(sigs)
		if !sig.VerifyAggregated(pubs, message, domain) {
			panic("bad")
		}
	}

	{
		priv, err := GenerateBlsKey()
		if err != nil {
			panic(err)
		}

		domain := mustDecodeBytes("508e30424791cb9a71683381558c3da1979b6fa423b2d6db1396b1d94d7c4a78")
		message := mustDecodeBytes("abcd")

		sig, err := priv.Sign(message, domain)
		if err != nil {
			panic(err)
		}

		if !sig.Verify(priv.PublicKey(), message, domain) {
			panic("bad")
		}
	}

	var expandMsgCases []struct {
		Msg    argBytes
		Result argBytes
	}
	decodeTestVector("testvectors/expandMsg.json", &expandMsgCases)

	for _, c := range expandMsgCases {
		res, err := expandMsgSHA256XMD(c.Msg, testvectorDomain, 2*48)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(res, c.Result) {
			panic("bad")
		}
	}

	var hashToFieldCases []struct {
		Msg argBytes
		X   argBig
		Y   argBig
	}
	decodeTestVector("testvectors/hashToField.json", &hashToFieldCases)

	for _, c := range hashToFieldCases {
		a, b, err := hashToField(c.Msg, testvectorDomain)
		if err != nil {
			panic(err)
		}

		if a.Cmp(c.X.Int()) != 0 {
			panic("bad a")
		}
		if b.Cmp(c.Y.Int()) != 0 {
			panic("bad b")
		}
	}

	var mapToPointCases []struct {
		E argBig
		X argBig
		Y argBig
	}
	decodeTestVector("testvectors/mapToPoint.json", &mapToPointCases)

	for _, c := range mapToPointCases {
		a, b := mapToPoint(c.E.Int())

		if a.Cmp(c.X.Int()) != 0 {
			panic("bad a")
		}
		if b.Cmp(c.Y.Int()) != 0 {
			panic("bad b")
		}
	}

	var hashToPointCases []struct {
		Msg    argBytes
		Domain argBytes
		X      argBig
		Y      argBig
	}

	decodeTestVector("testvectors/hashToPoint.json", &hashToPointCases)

	for _, c := range hashToPointCases {
		hashToPoint(c.Msg, c.Domain)

		// this test case is not correct, I copied the value x as both x and y...
		// but it works. Fix.

		//fmt.Println("----")
		//fmt.Println(g1.Marshal())
		//fmt.Println(c.X.Int().Bytes())
	}

}

// negated g2 point
var negG2Point = mustG2Point("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d")

// g2 point
var g2Point = mustG2Point("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa")

func mustG2Point(str string) *bn256.G2 {
	buf, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}

	b := new(bn256.G2)
	if _, err := b.Unmarshal(buf); err != nil {
		panic(err)
	}
	return b
}

type PrivateKey struct {
	s *big.Int
}

// GenerateBlsKey creates a random private and its corresponding public keys
func GenerateBlsKey() (*PrivateKey, error) {
	s, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{s: s}, nil
}

func (p *PrivateKey) PublicKey() *PublicKey {
	g2 := new(bn256.G2)
	g2 = g2.ScalarMult(g2Point, p.s)

	return &PublicKey{g2: g2}
}

func (p *PrivateKey) Marshal() ([]byte, error) {
	return p.s.Bytes(), nil
}

func (p *PrivateKey) Unmarshal(data []byte) error {
	s := new(big.Int)
	if err := s.UnmarshalJSON(data); err != nil {
		return err
	}
	p.s = s
	return nil
}

func (p *PrivateKey) Sign(message, domain []byte) (*Signature, error) {
	point := hashToPoint(message, domain)

	g1 := new(bn256.G1)
	g1 = g1.ScalarMult(point, p.s)

	return &Signature{g1: g1}, nil
}

type PublicKey struct {
	g2 *bn256.G2
}

func (p *PublicKey) Marshal() ([]byte, error) {
	return p.g2.Marshal(), nil
}

func (p *PublicKey) Unmarshal(data []byte) error {
	g2 := new(bn256.G2)
	if _, err := g2.Unmarshal(data); err != nil {
		return err
	}
	p.g2 = g2
	return nil
}

func (p *PublicKey) ToBigInt() [4]*big.Int {
	blsKey, err := p.Marshal()
	if err != nil {
		panic(err)
	}

	res := [4]*big.Int{
		new(big.Int).SetBytes(blsKey[32:64]),
		new(big.Int).SetBytes(blsKey[0:32]),
		new(big.Int).SetBytes(blsKey[96:128]),
		new(big.Int).SetBytes(blsKey[64:96]),
	}

	return res
}

type Signature struct {
	g1 *bn256.G1
}

func (s *Signature) Verify(pub *PublicKey, message, domain []byte) bool {
	point := hashToPoint(message, domain)

	return bn256.PairingCheck([]*bn256.G1{s.g1, point}, []*bn256.G2{negG2Point, pub.g2})
}

func (s *Signature) VerifyAggregated(publicKeys []*PublicKey, msg, domain []byte) bool {
	aggPubs := aggregatePublicKeys(publicKeys)

	return s.Verify(aggPubs, msg, domain)
}

func aggregateSignatures(sigs []*Signature) *Signature {
	g1 := new(bn256.G1)
	for _, sig := range sigs {
		g1 = g1.Add(g1, sig.g1)
	}
	return &Signature{g1: g1}
}

func (s *Signature) Marshal() ([]byte, error) {
	return s.g1.Marshal(), nil
}

func (s *Signature) Unmarshal(data []byte) error {
	g1 := new(bn256.G1)
	if _, err := g1.Unmarshal(data); err != nil {
		return err
	}
	s.g1 = g1
	return nil
}

// aggregatePublicKeys calculates P1 + P2 + ...
func aggregatePublicKeys(pubs []*PublicKey) *PublicKey {
	g2 := new(bn256.G2)
	for _, x := range pubs {
		g2 = g2.Add(g2, x.g2)
	}

	return &PublicKey{g2: g2}
}

func main11111() {

	/*
		-- hash to point --

		msg := mustDecodeBytes("fd7ead7342004b3a32ad")
		domain := mustDecodeBytes("602611de35678287e7fce135407021b7a06afed4cfbbbec5fad0f0ad583e67a1")

		fmt.Println(hashToField(msg, domain))

		fmt.Println(bn254.HashToField(msg, domain))

		fmt.Println(gbn254.HashToField(msg, domain))
	*/

	// -- map to point --

	num, _ := new(big.Int).SetString("6250852387127432895105140075089930644008053744394686327129773038454698876708", 10)

	fmt.Println(mapToPoint(num))

	elem := new(fp.Element).SetBigInt(num)
	g1 := gbn254.MapToG1(*elem)

	fmt.Println(g1.X.BigInt(new(big.Int)), g1.Y.BigInt(new(big.Int)))
}

func mainxx() {

	num, ok := new(big.Int).SetString("111273539074080998977425750430059747220713705637190454279514750311404001633", 10)
	if !ok {
		panic("bad")
	}

	mapToPoint(num)
}

// 32742958878823682879618375149989860927872657822640914410822075246648776621099642418053677771665762922185412495780255
// 523441800305950298265025260140324815984107602101921146440914095738571411762169736275358862143010770090293103666379

func main1111() {
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

	b2 := new(gbn254.G2Affine)
	if err := b2.Unmarshal(g2B); err != nil {
		panic(err)
	}
	b1 := new(gbn254.G1Affine)
	if err := b1.Unmarshal(g1B); err != nil {
		panic(err)
	}

	fmt.Println("------------- SHOW POINTS ----------------")

	fmt.Println(bn254.NewG2().ToBytes(pointG2))
	fmt.Println(bn254.NewG1().ToBytes(pointG1))

	fmt.Println(b2.Marshal())
	fmt.Println(b1.Marshal())

	fmt.Println("------------ MAP TO POINT -----------------")

	msg := mustDecodeBytes("fd7ead7342004b3a32ad")
	domain := mustDecodeBytes("602611de35678287e7fce135407021b7a06afed4cfbbbec5fad0f0ad583e67a1")

	m1, err := bn254.NewG1().HashToCurveFT(msg, domain)
	if err != nil {
		panic(err)
	}

	m2, err := gbn254.HashToG1(msg, domain)
	if err != nil {
		panic(err)
	}

	m3 := hashToPoint(msg, domain)

	fmt.Println(bn254.NewG1().ToBytes(m1))
	fmt.Println(m2.Marshal())
	fmt.Println(m3.Marshal())
}

func main222() {
	msg := mustDecodeBytes("fd7ead7342004b3a32ad")
	domain := mustDecodeBytes("602611de35678287e7fce135407021b7a06afed4cfbbbec5fad0f0ad583e67a1")

	M, err := bn254.NewG1().HashToCurveFT(msg, domain)
	if err != nil {
		panic(err)
	}
	fmt.Println(M)

	res, err := hashToFpXMDSHA256(msg, domain, 2)
	if err != nil {
		panic(err)
	}

	g1 := mapToG1Point(res[0])
	g2 := mapToG1Point(res[1])
	g1.Add(g1, g2)

	fmt.Println(bn254.NewG1().ToBytes(M))
	fmt.Println(g1.Marshal())
}

func hashToPoint(msg, domain []byte) *bn256.G1 {
	a, b, err := hashToField(msg, domain)
	if err != nil {
		panic(err)
	}

	//a = a.Mod(a, modulus)
	//b = b.Mod(b, modulus)

	g1 := mapToG1Point(a)
	g2 := mapToG1Point(b)
	g1.Add(g1, g2)

	return g1
}

func mapToG1Point(b *big.Int) *bn256.G1 {
	xx, yy := mapToPoint(b)

	pointBytes := bytes.Buffer{}
	pointBytes.Write(leftPad(xx.Bytes(), 32))
	pointBytes.Write(leftPad(yy.Bytes(), 32))

	// we have to pad left zero bytes to reach size of 64 bytes
	bb := pointBytes.Bytes()

	g1 := new(bn256.G1)
	_, err := g1.Unmarshal(bb)
	if err != nil {
		panic(err)
	}

	return g1
}

func leftPad(buf []byte, n int) []byte {
	l := len(buf)
	if l > n {
		return buf
	}

	tmp := make([]byte, n)
	copy(tmp[n-l:], buf)

	return tmp
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

var modulus, _ = new(big.Int).SetString("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16)
var zero = new(big.Int).SetInt64(0)

func hashToField(msg []byte, domain []byte) (*big.Int, *big.Int, error) {
	res, err := hashToFpXMDSHA256(msg, domain, 2)
	if err != nil {
		return nil, nil, err
	}
	return res[0], res[1], nil
}

func hashToFpXMDSHA256(msg []byte, domain []byte, count int) ([]*big.Int, error) {
	randBytes, err := expandMsgSHA256XMD(msg, domain, count*48)
	if err != nil {
		return nil, err
	}

	els := make([]*big.Int, count)
	for i := 0; i < count; i++ {
		num := new(big.Int).SetBytes(randBytes[i*48 : (i+1)*48])

		// fast path
		c := num.Cmp(modulus)
		if c == 0 {
			// nothing
		} else if c != 1 && num.Cmp(zero) != -1 {
			// 0 < v < q
		} else {
			num = num.Mod(num, modulus)
		}

		// copy input + modular reduction
		els[i] = num
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

type argBig big.Int

func (a *argBig) UnmarshalText(input []byte) error {
	b := new(big.Int)

	if strings.HasPrefix(string(input), "0x") {
		buf, err := decodeToHex(input)
		if err != nil {
			return err
		}

		b.SetBytes(buf)
	} else {
		// int in string format
		b.SetString(string(input), 10)
	}

	*a = argBig(*b)
	return nil
}

func (a *argBig) Int() *big.Int {
	return (*big.Int)(a)
}

type argUint64 uint64

func (u *argUint64) UnmarshalText(input []byte) error {
	str := strings.TrimPrefix(string(input), "0x")
	num, err := strconv.ParseUint(str, 16, 64)

	if err != nil {
		return err
	}

	*u = argUint64(num)

	return nil
}

type argBytes []byte

func (b *argBytes) UnmarshalText(input []byte) error {
	hh, err := decodeToHex(input)
	if err != nil {
		return nil
	}

	aux := make([]byte, len(hh))
	copy(aux[:], hh[:])
	*b = aux

	return nil
}

func decodeToHex(b []byte) ([]byte, error) {
	str := string(b)
	str = strings.TrimPrefix(str, "0x")

	if len(str)%2 != 0 {
		str = "0" + str
	}

	return hex.DecodeString(str)
}
