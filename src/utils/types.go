package utils

import "math/big"

// TierRatio 定义了资产的分层抵押率结构
type TierRatio struct {
	BoundaryValue    *big.Int // 该层级的边界值
	Ratio            uint8    // 该层级的抵押率(0-100)
	PrecomputedValue *big.Int // 预计算值,用于优化计算效率
}

// CexAssetInfo 定义了交易所中某个资产的完整信息
type CexAssetInfo struct {
	TotalEquity uint64 // 总权益
	TotalDebt   uint64 // 总债务
	BasePrice   uint64 // 基准价格
	Symbol      string // 资产符号
	Index       uint32 // 资产索引

	// 三种抵押品类型的数量
	LoanCollateral            uint64 // 贷款抵押品数量
	MarginCollateral          uint64 // 保证金抵押品数量
	PortfolioMarginCollateral uint64 // 投资组合保证金抵押品数量

	// 三种抵押品类型对应的分层抵押率配置
	LoanRatios            [TierCount]TierRatio // 贷款抵押率配置
	MarginRatios          [TierCount]TierRatio // 保证金抵押率配置
	PortfolioMarginRatios [TierCount]TierRatio // 投资组合保证金抵押率配置
}

// AccountAsset 定义了账户中某个资产的状态
type AccountAsset struct {
	Index           uint16 // 资产索引
	Equity          uint64 // 权益数量
	Debt            uint64 // 债务数量
	Loan            uint64 // 贷款抵押数量
	Margin          uint64 // 保证金数量
	PortfolioMargin uint64 // 投资组合保证金数量
}

// AccountInfo 定义了完整的账户信息
type AccountInfo struct {
	AccountIndex    uint32         // 账户索引
	AccountId       []byte         // 账户ID
	TotalEquity     *big.Int       // 总权益(所有资产)
	TotalDebt       *big.Int       // 总债务(所有资产)
	TotalCollateral *big.Int       // 总抵押品价值
	Assets          []AccountAsset // 账户拥有的资产列表
}

// CreateUserOperation 定义了创建用户的操作数据
type CreateUserOperation struct {
	BeforeAccountTreeRoot []byte                   // 操作前的账户树根哈希
	AfterAccountTreeRoot  []byte                   // 操作后的账户树根哈希
	Assets                []AccountAsset           // 用户的资产列表
	AccountIndex          uint32                   // 账户索引
	AccountIdHash         []byte                   // 账户ID的哈希值
	AccountProof          [AccountTreeDepth][]byte // 账户在Merkle树中的证明路径
}

// BatchCreateUserWitness 定义了批量创建用户的见证数据
type BatchCreateUserWitness struct {
	BatchCommitment           []byte // 批次承诺值
	BeforeAccountTreeRoot     []byte // 操作前的账户树根
	AfterAccountTreeRoot      []byte // 操作后的账户树根
	BeforeCEXAssetsCommitment []byte // 操作前的CEX资产承诺
	AfterCEXAssetsCommitment  []byte // 操作后的CEX资产承诺

	BeforeCexAssets []CexAssetInfo        // 操作前的CEX资产状态
	CreateUserOps   []CreateUserOperation // 批量创建用户的操作列表
}
