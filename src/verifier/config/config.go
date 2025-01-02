package config

import (
	"math/big"

	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
)

// Config 验证器配置结构
// 用于存储验证系统所需的全局配置信息
type Config struct {
	ProofTable       string               // 证明表名称
	ZkKeyName        []string             // 零知识证明密钥名称列表
	AssetsCountTiers []int                // 资产数量层级配置
	CexAssetsInfo    []utils.CexAssetInfo // CEX资产信息列表
}

// UserConfig 用户配置结构
// 用于存储单个用户的验证相关信息
type UserConfig struct {
	AccountIndex    uint32               // 账户索引
	AccountIdHash   string               // 账户ID哈希值
	TotalEquity     big.Int              // 总权益(精确计算)
	TotalDebt       big.Int              // 总债务(精确计算)
	TotalCollateral big.Int              // 总抵押品(精确计算)
	Root            string               // Merkle树根哈希
	Assets          []utils.AccountAsset // 用户资产列表
	Proof           []string             // Merkle证明路径
}
