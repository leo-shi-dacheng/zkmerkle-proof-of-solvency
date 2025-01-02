package circuit

import (
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/consensys/gnark/frontend"
)

// 类型别名定义
type (
	Variable = frontend.Variable // 电路变量类型
	API      = frontend.API      // 电路API接口
)

// TierRatio 定义分层比率结构
// 用于表示不同层级的抵押品比率配置
type TierRatio struct {
	BoundaryValue    Variable // 层级边界值
	Ratio            Variable // 该层级的比率值(百分比)
	PrecomputedValue Variable // 预计算值(用于优化)
}

// CexAssetInfo 中心化交易所资产信息
// 包含资产的总量、价格和各类抵押品配置
type CexAssetInfo struct {
	TotalEquity Variable // 总权益
	TotalDebt   Variable // 总债务
	BasePrice   Variable // 基础价格

	// 各类抵押品数量
	LoanCollateral            Variable // 贷款抵押品
	MarginCollateral          Variable // 保证金抵押品
	PortfolioMarginCollateral Variable // 投资组合保证金抵押品

	// 各类抵押品的分层比率配置
	LoanRatios            []TierRatio // 贷款比率配置
	MarginRatios          []TierRatio // 保证金比率配置
	PortfolioMarginRatios []TierRatio // 投资组合保证金比率配置
}

// UserAssetInfo 用户资产信息
// 记录用户资产的索引和抵押品配置信息
type UserAssetInfo struct {
	AssetIndex Variable // 资产索引

	// 贷款抵押品配置
	LoanCollateralIndex Variable // 贷款抵押品层级索引
	LoanCollateralFlag  Variable // 贷款抵押品标志(1表示超过最高层级)

	// 保证金抵押品配置
	MarginCollateralIndex Variable // 保证金抵押品层级索引
	MarginCollateralFlag  Variable // 保证金抵押品标志

	// 投资组合保证金抵押品配置
	PortfolioMarginCollateralIndex Variable // 投资组合保证金层级索引
	PortfolioMarginCollateralFlag  Variable // 投资组合保证金标志
}

// UserAssetMeta 用户资产元数据
// 记录用户资产的具体数量信息
type UserAssetMeta struct {
	Equity                    Variable // 权益数量
	Debt                      Variable // 债务数量
	LoanCollateral            Variable // 贷款抵押品数量
	MarginCollateral          Variable // 保证金抵押品数量
	PortfolioMarginCollateral Variable // 投资组合保证金数量
}

// CreateUserOperation 创建用户操作
// 定义创建用户时需要的所有信息
type CreateUserOperation struct {
	BeforeAccountTreeRoot Variable                         // 操作前账户树根
	AfterAccountTreeRoot  Variable                         // 操作后账户树根
	Assets                []UserAssetInfo                  // 用户资产信息列表
	AssetsForUpdateCex    []UserAssetMeta                  // 用于更新CEX的资产元数据
	AccountIndex          Variable                         // 账户索引
	AccountIdHash         Variable                         // 账户ID哈希
	AccountProof          [utils.AccountTreeDepth]Variable // 账户证明路径
}
