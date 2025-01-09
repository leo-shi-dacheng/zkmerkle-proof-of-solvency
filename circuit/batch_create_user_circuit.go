package circuit

import (
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/consensys/gnark/std/hash/poseidon"

	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/rangecheck"
)

// BatchCreateUserCircuit 定义批量创建用户的电路结构
type BatchCreateUserCircuit struct {
	// 公开输入
	BatchCommitment Variable `gnark:",public"` // 批次承诺(公开输入)
	// 私有输入
	BeforeAccountTreeRoot     Variable              // 操作前的账户树根
	AfterAccountTreeRoot      Variable              // 操作后的账户树根
	BeforeCEXAssetsCommitment Variable              // CEX资产承诺(操作前)
	AfterCEXAssetsCommitment  Variable              // CEX资产承诺(操作后)
	BeforeCexAssets           []CexAssetInfo        // CEX资产列表
	CreateUserOps             []CreateUserOperation // 用户创建操作列表
}

// NewVerifyBatchCreateUserCircuit 创建新的验证电路实例
func NewVerifyBatchCreateUserCircuit(commitment []byte) *BatchCreateUserCircuit {
	var v BatchCreateUserCircuit
	v.BatchCommitment = commitment
	return &v
}

// NewBatchCreateUserCircuit 创建新的批处理电路实例
func NewBatchCreateUserCircuit(userAssetCounts uint32, allAssetCounts uint32, batchCounts uint32) *BatchCreateUserCircuit {
	var circuit BatchCreateUserCircuit
	circuit.BatchCommitment = 0
	circuit.BeforeAccountTreeRoot = 0
	circuit.AfterAccountTreeRoot = 0
	circuit.BeforeCEXAssetsCommitment = 0
	circuit.AfterCEXAssetsCommitment = 0
	circuit.BeforeCexAssets = make([]CexAssetInfo, allAssetCounts)
	for i := uint32(0); i < allAssetCounts; i++ {
		circuit.BeforeCexAssets[i] = CexAssetInfo{
			TotalEquity:               0,
			TotalDebt:                 0,
			BasePrice:                 0,
			LoanCollateral:            0,
			MarginCollateral:          0,
			PortfolioMarginCollateral: 0,
			LoanRatios:                make([]TierRatio, utils.TierCount),
			MarginRatios:              make([]TierRatio, utils.TierCount),
			PortfolioMarginRatios:     make([]TierRatio, utils.TierCount),
		}
		for j := uint32(0); j < utils.TierCount; j++ {
			circuit.BeforeCexAssets[i].LoanRatios[j] = TierRatio{
				BoundaryValue:    0,
				Ratio:            0,
				PrecomputedValue: 0,
			}
			circuit.BeforeCexAssets[i].MarginRatios[j] = TierRatio{
				BoundaryValue:    0,
				Ratio:            0,
				PrecomputedValue: 0,
			}
			circuit.BeforeCexAssets[i].PortfolioMarginRatios[j] = TierRatio{
				BoundaryValue:    0,
				Ratio:            0,
				PrecomputedValue: 0,
			}
		}
	}
	circuit.CreateUserOps = make([]CreateUserOperation, batchCounts)
	for i := uint32(0); i < batchCounts; i++ {
		circuit.CreateUserOps[i] = CreateUserOperation{
			BeforeAccountTreeRoot: 0,
			AfterAccountTreeRoot:  0,
			Assets:                make([]UserAssetInfo, userAssetCounts),
			AssetsForUpdateCex:    make([]UserAssetMeta, allAssetCounts),
			AccountIndex:          0,
			AccountIdHash:         0,
			AccountProof:          [utils.AccountTreeDepth]Variable{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		}
		for j := uint32(0); j < allAssetCounts; j++ {
			circuit.CreateUserOps[i].AssetsForUpdateCex[j].Debt = 0
			circuit.CreateUserOps[i].AssetsForUpdateCex[j].Equity = 0
			circuit.CreateUserOps[i].AssetsForUpdateCex[j].LoanCollateral = 0
			circuit.CreateUserOps[i].AssetsForUpdateCex[j].MarginCollateral = 0
			circuit.CreateUserOps[i].AssetsForUpdateCex[j].PortfolioMarginCollateral = 0
		}
		for j := uint32(0); j < userAssetCounts; j++ {
			circuit.CreateUserOps[i].Assets[j] = UserAssetInfo{
				AssetIndex:                     j,
				LoanCollateralIndex:            0,
				LoanCollateralFlag:             0,
				MarginCollateralIndex:          0,
				MarginCollateralFlag:           0,
				PortfolioMarginCollateralIndex: 0,
				PortfolioMarginCollateralFlag:  0,
			}
		}
	}
	return &circuit
}

// Define 实现批量创建用户的电路约束逻辑
// 主要验证步骤:
// 1. 批次承诺验证
// 2. CEX资产状态验证
// 3. 用户资产验证
// 4. Merkle树更新验证
// 5. 状态转换验证
// 6. 最终状态验证
func (b BatchCreateUserCircuit) Define(api API) error {
	// 第1步: 验证批次承诺
	// 使用Poseidon哈希验证批次承诺的正确性
	actualBatchCommitment := poseidon.Poseidon(api,
		b.BeforeAccountTreeRoot,     // 操作前账户树根
		b.AfterAccountTreeRoot,      // 操作后账户树根
		b.BeforeCEXAssetsCommitment, // 操作前CEX资产承诺
		b.AfterCEXAssetsCommitment)  // 操作后CEX资产承诺
	api.AssertIsEqual(b.BatchCommitment, actualBatchCommitment)

	// 准备CEX资产验证
	countOfCexAsset := getVariableCountOfCexAsset(b.BeforeCexAssets[0])
	cexAssets := make([]Variable, len(b.BeforeCexAssets)*countOfCexAsset)
	afterCexAssets := make([]CexAssetInfo, len(b.BeforeCexAssets))

	// 初始化范围检查器
	r := rangecheck.New(api)

	// 第2步: CEX资产状态验证
	// 创建资产价格查找表
	assetPriceTable := logderivlookup.New(api)
	for i := 0; i < len(b.BeforeCexAssets); i++ {
		// 验证资产数量范围(64位)
		r.Check(b.BeforeCexAssets[i].TotalEquity, 64)               // 总权益
		r.Check(b.BeforeCexAssets[i].TotalDebt, 64)                 // 总债务
		r.Check(b.BeforeCexAssets[i].BasePrice, 64)                 // 基础价格
		r.Check(b.BeforeCexAssets[i].LoanCollateral, 64)            // 贷款抵押品
		r.Check(b.BeforeCexAssets[i].MarginCollateral, 64)          // 保证金抵押品
		r.Check(b.BeforeCexAssets[i].PortfolioMarginCollateral, 64) // 投资组合保证金

		// 填充CEX资产承诺
		fillCexAssetCommitment(api, b.BeforeCexAssets[i], i, cexAssets)

		// 生成快速抵押品计算
		generateRapidArithmeticForCollateral(api, r, b.BeforeCexAssets[i].LoanRatios)
		generateRapidArithmeticForCollateral(api, r, b.BeforeCexAssets[i].MarginRatios)
		generateRapidArithmeticForCollateral(api, r, b.BeforeCexAssets[i].PortfolioMarginRatios)

		afterCexAssets[i] = b.BeforeCexAssets[i]
		// 添加资产价格到查找表
		assetPriceTable.Insert(b.BeforeCexAssets[i].BasePrice)
	}

	// 验证CEX资产承诺的正确性
	actualCexAssetsCommitment := poseidon.Poseidon(api, cexAssets...)
	api.AssertIsEqual(b.BeforeCEXAssetsCommitment, actualCexAssetsCommitment)

	// 验证账户树根的连续性
	api.AssertIsEqual(b.BeforeAccountTreeRoot, b.CreateUserOps[0].BeforeAccountTreeRoot)
	api.AssertIsEqual(b.AfterAccountTreeRoot, b.CreateUserOps[len(b.CreateUserOps)-1].AfterAccountTreeRoot)

	// 构建抵押品比率查找表
	loanTierRatiosTable := constructLoanTierRatiosLookupTable(api, b.BeforeCexAssets)
	marginTierRatiosTable := constructMarginTierRatiosLookupTable(api, b.BeforeCexAssets)
	portfolioMarginTierRatiosTable := constructPortfolioTierRatiosLookupTable(api, b.BeforeCexAssets)

	// 用于资产ID哈希的数组
	userAssetIdHashes := make([]Variable, len(b.CreateUserOps)+1)

	// 用于用户资产验证的数组
	userAssetsResults := make([][]Variable, len(b.CreateUserOps))
	userAssetsQueries := make([][]Variable, len(b.CreateUserOps))

	// 第3步: 验证每个用户操作
	for i := 0; i < len(b.CreateUserOps); i++ {
		accountIndexHelper := accountIdToMerkleHelper(api, b.CreateUserOps[i].AccountIndex)
		verifyMerkleProof(api, b.CreateUserOps[i].BeforeAccountTreeRoot, EmptyAccountLeafNodeHash, b.CreateUserOps[i].AccountProof[:], accountIndexHelper)
		var totalUserEquity Variable = 0
		var totalUserDebt Variable = 0
		userAssets := b.CreateUserOps[i].Assets
		var totalUserCollateralRealValue Variable = 0

		// construct lookup table for user assets
		userAssetsLookupTable := logderivlookup.New(api)
		for j := 0; j < len(b.CreateUserOps[i].AssetsForUpdateCex); j++ {
			userAssetsLookupTable.Insert(b.CreateUserOps[i].AssetsForUpdateCex[j].Equity)
			userAssetsLookupTable.Insert(b.CreateUserOps[i].AssetsForUpdateCex[j].Debt)
			userAssetsLookupTable.Insert(b.CreateUserOps[i].AssetsForUpdateCex[j].LoanCollateral)
			userAssetsLookupTable.Insert(b.CreateUserOps[i].AssetsForUpdateCex[j].MarginCollateral)
			userAssetsLookupTable.Insert(b.CreateUserOps[i].AssetsForUpdateCex[j].PortfolioMarginCollateral)
		}

		// To check all the user assetIndexes are unique to each other.
		// If the user assetIndex is increasing, Then all the assetIndexes are unique
		for j := 0; j < len(userAssets)-1; j++ {
			r.Check(userAssets[j].AssetIndex, 16)
			cr := api.CmpNOp(userAssets[j+1].AssetIndex, userAssets[j].AssetIndex, 16, true)
			api.AssertIsEqual(cr, 1)
		}

		// one Variable can store 15 assetIds, one assetId is less than 16 bits
		assetIdsToVariables := make([]Variable, (len(userAssets)+14)/15)
		for j := 0; j < len(assetIdsToVariables); j++ {
			var v Variable = 0
			for p := j * 15; p < (j+1)*15 && p < len(userAssets); p++ {
				v = api.Add(v, api.Mul(userAssets[p].AssetIndex, utils.PowersOfSixteenBits[p%15]))
			}
			assetIdsToVariables[j] = v
		}
		userAssetIdHashes[i] = poseidon.Poseidon(api, assetIdsToVariables...)

		// construct query to get user assets
		userAssetsQueries[i] = make([]Variable, len(userAssets)*5)
		assetPriceQueries := make([]Variable, len(userAssets))
		numOfAssetsFields := 6
		for j := 0; j < len(userAssets); j++ {
			p := api.Mul(userAssets[j].AssetIndex, 5)
			for k := 0; k < 5; k++ {
				userAssetsQueries[i][j*5+k] = api.Add(p, k)
			}
			assetPriceQueries[j] = userAssets[j].AssetIndex
		}
		userAssetsResults[i] = userAssetsLookupTable.Lookup(userAssetsQueries[i]...)
		assetPriceResponses := assetPriceTable.Lookup(assetPriceQueries...)

		flattenAssetFieldsForHash := make([]Variable, len(userAssets)*numOfAssetsFields)
		for j := 0; j < len(userAssets); j++ {
			// Equity
			userEquity := userAssetsResults[i][j*5]
			r.Check(userEquity, 64)
			// Debt
			userDebt := userAssetsResults[i][j*5+1]
			r.Check(userDebt, 64)
			// LoanCollateral
			userLoanCollateral := userAssetsResults[i][j*5+2]
			r.Check(userLoanCollateral, 64)
			// MarginCollateral
			userMarginCollateral := userAssetsResults[i][j*5+3]
			r.Check(userMarginCollateral, 64)
			// PortfolioMarginCollateral
			userPortfolioMarginCollateral := userAssetsResults[i][j*5+4]
			r.Check(userPortfolioMarginCollateral, 64)

			flattenAssetFieldsForHash[j*numOfAssetsFields] = userAssets[j].AssetIndex
			flattenAssetFieldsForHash[j*numOfAssetsFields+1] = userEquity
			flattenAssetFieldsForHash[j*numOfAssetsFields+2] = userDebt
			flattenAssetFieldsForHash[j*numOfAssetsFields+3] = userLoanCollateral
			flattenAssetFieldsForHash[j*numOfAssetsFields+4] = userMarginCollateral
			flattenAssetFieldsForHash[j*numOfAssetsFields+5] = userPortfolioMarginCollateral

			assetTotalCollateral := api.Add(userLoanCollateral, userMarginCollateral, userPortfolioMarginCollateral)
			r.Check(assetTotalCollateral, 64)
			api.AssertIsLessOrEqualNOp(assetTotalCollateral, userEquity, 64, true)

			loanRealValue := getAndCheckTierRatiosQueryResults(api, r, loanTierRatiosTable, userAssets[j].AssetIndex,
				userLoanCollateral,
				userAssets[j].LoanCollateralIndex,
				userAssets[j].LoanCollateralFlag,
				assetPriceResponses[j],
				3*(len(b.BeforeCexAssets[j].LoanRatios)+1))

			marginRealValue := getAndCheckTierRatiosQueryResults(api, r, marginTierRatiosTable, userAssets[j].AssetIndex,
				userMarginCollateral,
				userAssets[j].MarginCollateralIndex,
				userAssets[j].MarginCollateralFlag,
				assetPriceResponses[j],
				3*(len(b.BeforeCexAssets[j].MarginRatios)+1))

			portfolioMarginRealValue := getAndCheckTierRatiosQueryResults(api, r, portfolioMarginTierRatiosTable, userAssets[j].AssetIndex,
				userPortfolioMarginCollateral,
				userAssets[j].PortfolioMarginCollateralIndex,
				userAssets[j].PortfolioMarginCollateralFlag,
				assetPriceResponses[j],
				3*(len(b.BeforeCexAssets[j].PortfolioMarginRatios)+1))

			totalUserCollateralRealValue = api.Add(totalUserCollateralRealValue, loanRealValue, marginRealValue, portfolioMarginRealValue)

			totalUserEquity = api.Add(totalUserEquity, api.Mul(userEquity, assetPriceResponses[j]))
			totalUserDebt = api.Add(totalUserDebt, api.Mul(userDebt, assetPriceResponses[j]))
		}

		for j := 0; j < len(b.CreateUserOps[i].AssetsForUpdateCex); j++ {
			afterCexAssets[j].TotalEquity = api.Add(afterCexAssets[j].TotalEquity, b.CreateUserOps[i].AssetsForUpdateCex[j].Equity)
			afterCexAssets[j].TotalDebt = api.Add(afterCexAssets[j].TotalDebt, b.CreateUserOps[i].AssetsForUpdateCex[j].Debt)
			afterCexAssets[j].LoanCollateral = api.Add(afterCexAssets[j].LoanCollateral, b.CreateUserOps[i].AssetsForUpdateCex[j].LoanCollateral)
			afterCexAssets[j].MarginCollateral = api.Add(afterCexAssets[j].MarginCollateral, b.CreateUserOps[i].AssetsForUpdateCex[j].MarginCollateral)
			afterCexAssets[j].PortfolioMarginCollateral = api.Add(afterCexAssets[j].PortfolioMarginCollateral, b.CreateUserOps[i].AssetsForUpdateCex[j].PortfolioMarginCollateral)
		}

		// make sure user's total Debt is less or equal than total collateral
		r.Check(totalUserDebt, 128)
		r.Check(totalUserCollateralRealValue, 128)
		api.AssertIsLessOrEqualNOp(totalUserDebt, totalUserCollateralRealValue, 128, true)
		userAssetsCommitment := computeUserAssetsCommitment(api, flattenAssetFieldsForHash)
		accountHash := poseidon.Poseidon(api, b.CreateUserOps[i].AccountIdHash, totalUserEquity, totalUserDebt, totalUserCollateralRealValue, userAssetsCommitment)
		actualAccountTreeRoot := updateMerkleProof(api, accountHash, b.CreateUserOps[i].AccountProof[:], accountIndexHelper)
		api.AssertIsEqual(actualAccountTreeRoot, b.CreateUserOps[i].AfterAccountTreeRoot)
	}

	// make sure user assets contains all non-zero assets of AssetsForUpdateCex
	// use random linear combination to check, the random number is poseidon hash of two elements:
	// 1. the public input of circuit -- batch commitment
	// 2. the poseidon hash of user assets index

	userAssetIdHashes[len(b.CreateUserOps)] = b.BatchCommitment
	randomChallenge := poseidon.Poseidon(api, userAssetIdHashes...)
	powersOfRandomChallenge := make([]Variable, 5*len(b.BeforeCexAssets))
	powersOfRandomChallenge[0] = randomChallenge
	powersOfRandomChallengeLookupTable := logderivlookup.New(api)
	powersOfRandomChallengeLookupTable.Insert(randomChallenge)
	for i := 1; i < len(powersOfRandomChallenge); i++ {
		powersOfRandomChallenge[i] = api.Mul(powersOfRandomChallenge[i-1], randomChallenge)
		powersOfRandomChallengeLookupTable.Insert(powersOfRandomChallenge[i])
	}

	for i := 0; i < len(b.CreateUserOps); i++ {
		powersOfRCResults := powersOfRandomChallengeLookupTable.Lookup(userAssetsQueries[i]...)
		var sumA Variable = 0
		for j := 0; j < len(powersOfRCResults); j++ {
			sumA = api.Add(sumA, api.Mul(powersOfRCResults[j], userAssetsResults[i][j]))
		}

		var sumB Variable = 0
		for j := 0; j < len(b.CreateUserOps[i].AssetsForUpdateCex); j++ {
			sumB = api.Add(sumB, api.Mul(b.CreateUserOps[i].AssetsForUpdateCex[j].Equity, powersOfRandomChallenge[5*j]))
			sumB = api.Add(sumB, api.Mul(b.CreateUserOps[i].AssetsForUpdateCex[j].Debt, powersOfRandomChallenge[5*j+1]))
			sumB = api.Add(sumB, api.Mul(b.CreateUserOps[i].AssetsForUpdateCex[j].LoanCollateral, powersOfRandomChallenge[5*j+2]))
			sumB = api.Add(sumB, api.Mul(b.CreateUserOps[i].AssetsForUpdateCex[j].MarginCollateral, powersOfRandomChallenge[5*j+3]))
			sumB = api.Add(sumB, api.Mul(b.CreateUserOps[i].AssetsForUpdateCex[j].PortfolioMarginCollateral, powersOfRandomChallenge[5*j+4]))
		}
		api.AssertIsEqual(sumA, sumB)
	}
	tempAfterCexAssets := make([]Variable, len(b.BeforeCexAssets)*countOfCexAsset)
	for j := 0; j < len(b.BeforeCexAssets); j++ {
		r.Check(afterCexAssets[j].TotalEquity, 64)
		r.Check(afterCexAssets[j].TotalDebt, 64)
		r.Check(afterCexAssets[j].LoanCollateral, 64)
		r.Check(afterCexAssets[j].MarginCollateral, 64)
		r.Check(afterCexAssets[j].PortfolioMarginCollateral, 64)

		fillCexAssetCommitment(api, afterCexAssets[j], j, tempAfterCexAssets)
	}

	// verify AfterCEXAssetsCommitment is computed correctly
	actualAfterCEXAssetsCommitment := poseidon.Poseidon(api, tempAfterCexAssets...)
	api.AssertIsEqual(actualAfterCEXAssetsCommitment, b.AfterCEXAssetsCommitment)
	api.Println("actualAfterCEXAssetsCommitment: ", actualAfterCEXAssetsCommitment)
	api.Println("AfterCEXAssetsCommitment: ", b.AfterCEXAssetsCommitment)
	for i := 0; i < len(b.CreateUserOps)-1; i++ {
		api.AssertIsEqual(b.CreateUserOps[i].AfterAccountTreeRoot, b.CreateUserOps[i+1].BeforeAccountTreeRoot)
	}
	return nil
}

func copyTierRatios(dst []TierRatio, src []utils.TierRatio) {
	for i := 0; i < len(dst); i++ {
		dst[i].BoundaryValue = src[i].BoundaryValue
		dst[i].Ratio = src[i].Ratio
		dst[i].PrecomputedValue = src[i].PrecomputedValue
	}

}

// SetBatchCreateUserCircuitWitness 将见证数据转换为电路格式
// 参数:
//   - batchWitness: 批量创建用户的见证数据
//
// 返回:
//   - witness: 转换后的电路见证数据
//   - err: 错误信息
func SetBatchCreateUserCircuitWitness(batchWitness *utils.BatchCreateUserWitness) (witness *BatchCreateUserCircuit, err error) {
	// 初始化电路见证数据结构
	witness = &BatchCreateUserCircuit{
		BatchCommitment:           batchWitness.BatchCommitment,                                 // 批次承诺
		BeforeAccountTreeRoot:     batchWitness.BeforeAccountTreeRoot,                           // 操作前账户树根
		AfterAccountTreeRoot:      batchWitness.AfterAccountTreeRoot,                            // 操作后账户树根
		BeforeCEXAssetsCommitment: batchWitness.BeforeCEXAssetsCommitment,                       // CEX资产承诺(前)
		AfterCEXAssetsCommitment:  batchWitness.AfterCEXAssetsCommitment,                        // CEX资产承诺(后)
		BeforeCexAssets:           make([]CexAssetInfo, len(batchWitness.BeforeCexAssets)),      // CEX资产列表
		CreateUserOps:             make([]CreateUserOperation, len(batchWitness.CreateUserOps)), // 用户创建操作列表
	}

	// 转换CEX资产数据
	for i := 0; i < len(witness.BeforeCexAssets); i++ {
		// 复制基本资产信息
		witness.BeforeCexAssets[i].TotalEquity = batchWitness.BeforeCexAssets[i].TotalEquity
		witness.BeforeCexAssets[i].TotalDebt = batchWitness.BeforeCexAssets[i].TotalDebt
		witness.BeforeCexAssets[i].BasePrice = batchWitness.BeforeCexAssets[i].BasePrice
		witness.BeforeCexAssets[i].LoanCollateral = batchWitness.BeforeCexAssets[i].LoanCollateral
		witness.BeforeCexAssets[i].MarginCollateral = batchWitness.BeforeCexAssets[i].MarginCollateral
		witness.BeforeCexAssets[i].PortfolioMarginCollateral = batchWitness.BeforeCexAssets[i].PortfolioMarginCollateral

		// 复制抵押品比率配置
		witness.BeforeCexAssets[i].LoanRatios = make([]TierRatio, len(batchWitness.BeforeCexAssets[i].LoanRatios))
		copyTierRatios(witness.BeforeCexAssets[i].LoanRatios, batchWitness.BeforeCexAssets[i].LoanRatios[:])

		witness.BeforeCexAssets[i].MarginRatios = make([]TierRatio, len(batchWitness.BeforeCexAssets[i].MarginRatios))
		copyTierRatios(witness.BeforeCexAssets[i].MarginRatios, batchWitness.BeforeCexAssets[i].MarginRatios[:])

		witness.BeforeCexAssets[i].PortfolioMarginRatios = make([]TierRatio, len(batchWitness.BeforeCexAssets[i].PortfolioMarginRatios))
		copyTierRatios(witness.BeforeCexAssets[i].PortfolioMarginRatios, batchWitness.BeforeCexAssets[i].PortfolioMarginRatios[:])
	}

	// 获取CEX资产总数和目标资产数量
	cexAssetsCount := len(witness.BeforeCexAssets)
	// 根据第一个用户的非空资产数量确定目标数量
	// 因为同一批次中所有用户的资产数量相同，其他用户可能是填充账户
	targetCounts := utils.GetNonEmptyAssetsCountOfUser(batchWitness.CreateUserOps[0].Assets)

	// 转换用户操作数据
	for i := 0; i < len(witness.CreateUserOps); i++ {
		// 复制账户树根
		witness.CreateUserOps[i].BeforeAccountTreeRoot = batchWitness.CreateUserOps[i].BeforeAccountTreeRoot
		witness.CreateUserOps[i].AfterAccountTreeRoot = batchWitness.CreateUserOps[i].AfterAccountTreeRoot
		witness.CreateUserOps[i].AssetsForUpdateCex = make([]UserAssetMeta, cexAssetsCount)

		// 收集现有资产的键
		existingKeys := make([]int, 0)
		for j := 0; j < len(batchWitness.CreateUserOps[i].Assets); j++ {
			u := batchWitness.CreateUserOps[i].Assets[j]
			// 转换用户资产元数据
			userAsset := UserAssetMeta{
				Equity:                    u.Equity,
				Debt:                      u.Debt,
				LoanCollateral:            u.Loan,
				MarginCollateral:          u.Margin,
				PortfolioMarginCollateral: u.PortfolioMargin,
			}

			witness.CreateUserOps[i].AssetsForUpdateCex[j] = userAsset

			// 收集非空资产的索引
			if !utils.IsAssetEmpty(&u) {
				existingKeys = append(existingKeys, int(u.Index))
			}
		}

		// 计算需要填充的资产数量
		paddingCounts := targetCounts - len(existingKeys)
		witness.CreateUserOps[i].Assets = make([]UserAssetInfo, targetCounts)
		currentPaddingCounts := 0
		currentAssetIndex := 0
		index := 0

		// 填充资产数组
		for _, v := range existingKeys {
			// 在实际资产之间添加填充资产
			if currentPaddingCounts < paddingCounts {
				for k := currentAssetIndex; k < v; k++ {
					currentPaddingCounts += 1
					// 添加空资产
					witness.CreateUserOps[i].Assets[index] = UserAssetInfo{
						AssetIndex:                     uint32(k),
						LoanCollateralIndex:            0,
						LoanCollateralFlag:             0,
						MarginCollateralIndex:          0,
						MarginCollateralFlag:           0,
						PortfolioMarginCollateralIndex: 0,
						PortfolioMarginCollateralFlag:  0,
					}
					index += 1
					if currentPaddingCounts >= paddingCounts {
						break
					}
				}
			}

			// 添加实际资产
			var uAssetInfo UserAssetInfo
			uAssetInfo.AssetIndex = uint32(v)
			// 计算并设置抵押品信息
			calcAndSetCollateralInfo(v, &uAssetInfo, &batchWitness.CreateUserOps[i].Assets[v], batchWitness.BeforeCexAssets)
			witness.CreateUserOps[i].Assets[index] = uAssetInfo
			index += 1
			currentAssetIndex = v + 1
		}

		// 填充剩余的空资产
		for k := index; k < targetCounts; k++ {
			witness.CreateUserOps[i].Assets[k] = UserAssetInfo{
				AssetIndex:                     uint32(currentAssetIndex),
				LoanCollateralIndex:            0,
				LoanCollateralFlag:             0,
				MarginCollateralIndex:          0,
				MarginCollateralFlag:           0,
				PortfolioMarginCollateralIndex: 0,
				PortfolioMarginCollateralFlag:  0,
			}
			currentAssetIndex += 1
		}

		// 复制账户信息
		witness.CreateUserOps[i].AccountIdHash = batchWitness.CreateUserOps[i].AccountIdHash
		witness.CreateUserOps[i].AccountIndex = batchWitness.CreateUserOps[i].AccountIndex
		for j := 0; j < len(witness.CreateUserOps[i].AccountProof); j++ {
			witness.CreateUserOps[i].AccountProof[j] = batchWitness.CreateUserOps[i].AccountProof[j]
		}
	}
	return witness, nil
}
