package utils

import (
	// "fmt"
	"math/big"
	"sort"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
)

const (
	AccountTreeDepth = 28      // Merkle树深度,支持2^28个账户
	AssetCounts      = 500     // 支持的最大资产数量
	TierCount        = 12      // 抵押率分层数量(必须是偶数)
	R1csBatchSize    = 1000000 // R1CS约束系统的批处理大小
)

var (
	// 用于计算的常用大数
	ZeroBigInt                    = new(big.Int).SetInt64(0)                                           // 0
	OneBigInt                     = new(big.Int).SetInt64(1)                                           // 1
	PercentageMultiplier          = new(big.Int).SetUint64(100)                                        // 百分比乘数
	MaxTierBoundaryValue, _       = new(big.Int).SetString("332306998946228968225951765070086144", 10) // 最大分层边界值 (2^118)
	Uint64MaxValueBigInt, _       = new(big.Int).SetString("18446744073709551616", 10)
	Uint64MaxValueBigIntSquare, _ = new(big.Int).SetString("340282366920938463463374607431768211456", 10)
	Uint8MaxValueBigInt, _        = new(big.Int).SetString("256", 10)
	Uint16MaxValueBigInt, _       = new(big.Int).SetString("65536", 10)
	Uint126MaxValueBigInt, _      = new(big.Int).SetString("85070591730234615865843651857942052864", 10)
	Uint134MaxValueBigInt, _      = new(big.Int).SetString("21778071482940061661655974875633165533184", 10)
	Uint64MaxValueFr              = new(fr.Element).SetBigInt(Uint64MaxValueBigInt)
	Uint64MaxValueFrSquare        = new(fr.Element).SetBigInt(Uint64MaxValueBigIntSquare)
	Uint8MaxValueFr               = new(fr.Element).SetBigInt(Uint8MaxValueBigInt)
	Uint16MaxValueFr              = new(fr.Element).SetBigInt(Uint16MaxValueBigInt)
	Uint126MaxValueFr             = new(fr.Element).SetBigInt(Uint126MaxValueBigInt)
	Uint134MaxValueFr             = new(fr.Element).SetBigInt(Uint134MaxValueBigInt)
	MaxTierBoundaryValueFr        = new(fr.Element).SetBigInt(MaxTierBoundaryValue)
	PercentageMultiplierFr        = new(fr.Element).SetBigInt(PercentageMultiplier)

	// 资产精度配置
	AssetTypeForTwoDigits = map[string]bool{
		"BTTC":       true,
		"bttc":       true,
		"SHIB":       true,
		"shib":       true,
		"LUNC":       true,
		"lunc":       true,
		"XEC":        true,
		"xec":        true,
		"WIN":        true,
		"win":        true,
		"BIDR":       true,
		"bidr":       true,
		"SPELL":      true,
		"spell":      true,
		"HOT":        true,
		"hot":        true,
		"DOGE":       true,
		"doge":       true,
		"PEPE":       true,
		"pepe":       true,
		"FLOKI":      true,
		"floki":      true,
		"IDRT":       true,
		"idrt":       true,
		"DOGS":       true,
		"dogs":       true,
		"BONK":       true,
		"bonk":       true,
		"1000SATS":   true,
		"1000sats":   true,
		"NEIRO":      true,
		"neiro":      true,
		"1000PEPPER": true,
		"1000pepper": true,
		"NOT":        true,
		"not":        true,
		"NFT":        true,
		"nft":        true,
		"BOME":       true,
		"bome":       true,
		"1MBABYDOGE": true,
		"1mbabydoge": true,
	}
	// the key is the number of assets user own
	// the value is the number of batch create user ops
	// 500种资产的用户每批92个
	// 50种资产的用户每批700个
	BatchCreateUserOpsCountsTiers = map[int]int{
		500: 92,
		50:  700,
	}
	AssetCountsTiers = make([]int, 0)

	// one Fr element is 252 bits, it contains 16 16-bit elements at most
	PowersOfSixteenBits [15]fr.Element
)

func init() {
	initValue := new(big.Int).SetUint64(1)
	for i := 0; i < 15; i++ {
		PowersOfSixteenBits[i].SetBigInt(initValue)
		initValue.Mul(initValue, big.NewInt(65536))
	}
	for k := range BatchCreateUserOpsCountsTiers {
		AssetCountsTiers = append(AssetCountsTiers, k)
	}
	sort.Ints(AssetCountsTiers)

	zero := &fr.Element{0, 0, 0, 0}
	tempHash := poseidon.Poseidon(zero, zero, zero, zero, zero).Bytes()
	NilAccountHash = tempHash[:]
	// fmt.Printf("NilAccountHash: %x\n", NilAccountHash)
}
