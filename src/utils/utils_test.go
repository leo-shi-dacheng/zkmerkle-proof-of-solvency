package utils

import (
	// "encoding/hex"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	// "github.com/stretchr/testify/assert"
	"encoding/csv"
	"math/big"
	"testing"
)

// 用于测试环境下计算用户资产的承诺值
func ComputeAssetsCommitmentForTest(userAssets []AccountAsset) []byte {
	// 1. 计算需要的元素数量: 每个资产有5个字段,每3个元素一组进行哈希
	nEles := (AssetCounts*5 + 2) / 3
	// 2. 创建扁平化的资产数组
	flattenUserAssets := make([]uint64, 3*nEles)

	// 3. 将用户资产数据展平到数组中
	for i := 0; i < AssetCounts; i++ {
		flattenUserAssets[5*i] = userAssets[i].Equity            // 权益
		flattenUserAssets[5*i+1] = userAssets[i].Debt            // 债务
		flattenUserAssets[5*i+2] = userAssets[i].Loan            // 贷款
		flattenUserAssets[5*i+3] = userAssets[i].Margin          // 保证金
		flattenUserAssets[5*i+4] = userAssets[i].PortfolioMargin // 投资组合保证金
	}

	// 4. 使用Poseidon哈希计算承诺值
	hasher := poseidon.NewPoseidon()
	// 5. 对每三个元素进行哈希计算
	for i := 0; i < nEles; i++ {
		// 计算: a*MAX^2 + b*MAX + c
		aBigInt := new(big.Int).SetUint64(flattenUserAssets[3*i])
		bBigInt := new(big.Int).SetUint64(flattenUserAssets[3*i+1])
		cBigInt := new(big.Int).SetUint64(flattenUserAssets[3*i+2])
		sumBigIntBytes := new(big.Int).Add(
			new(big.Int).Add(
				new(big.Int).Mul(aBigInt, Uint64MaxValueBigIntSquare),
				new(big.Int).Mul(bBigInt, Uint64MaxValueBigInt)),
			cBigInt).Bytes()
		hasher.Write(sumBigIntBytes)
	}

	return hasher.Sum(nil)
}

func TestComputeUserAssetsCommitment(t *testing.T) {
	userAssets := make([]AccountAsset, AssetCounts) // 创建用户资产数组
	testUserAssets1 := make([]AccountAsset, 10)     // 创建测试用户资产数组
	for i := 0; i < 10; i++ {
		// 设置测试资产的各个字段
		testUserAssets1[i].Index = uint16(3 * i)
		testUserAssets1[i].Equity = uint64(i*10 + 1000)
		testUserAssets1[i].Debt = uint64(i*10 + 500)
		testUserAssets1[i].Loan = uint64(i*10 + 100)
		testUserAssets1[i].Margin = uint64(i*10 + 100)
		testUserAssets1[i].PortfolioMargin = uint64(i*10 + 100)
		// 将测试数据复制到完整资产列表
		userAssets[testUserAssets1[i].Index].Equity = testUserAssets1[i].Equity
		userAssets[testUserAssets1[i].Index].Debt = testUserAssets1[i].Debt
		userAssets[testUserAssets1[i].Index].Loan = testUserAssets1[i].Loan
		userAssets[testUserAssets1[i].Index].Margin = testUserAssets1[i].Margin
		userAssets[testUserAssets1[i].Index].PortfolioMargin = testUserAssets1[i].PortfolioMargin
	}
	// 设置所有资产的索引
	for i := 0; i < AssetCounts; i++ {
		userAssets[i].Index = uint16(i)
	}
	// 计算期望的哈希值
	expectHash := ComputeAssetsCommitmentForTest(userAssets)
	// 计算实际的哈希值
	hasher := poseidon.NewPoseidon()
	hasher.Reset()
	actualHash := ComputeUserAssetsCommitment(&hasher, testUserAssets1)
	if string(expectHash) != string(actualHash) {
		t.Errorf("not match: %x:%x\n", expectHash, actualHash)
	}

	// case 2
	userAssets = make([]AccountAsset, AssetCounts)
	for i := 0; i < AssetCounts; i++ {
		userAssets[i].Index = uint16(i)
	}
	for i := 0; i < 10; i++ {
		testUserAssets1[i].Index = uint16(3*i) + 2
		testUserAssets1[i].Equity = uint64(i*10 + 1000)
		testUserAssets1[i].Debt = uint64(i*10 + 500)
		testUserAssets1[i].Loan = uint64(i*10 + 100)
		testUserAssets1[i].Margin = uint64(i*10 + 100)
		testUserAssets1[i].PortfolioMargin = uint64(i*10 + 100)

		userAssets[testUserAssets1[i].Index].Equity = testUserAssets1[i].Equity
		userAssets[testUserAssets1[i].Index].Debt = testUserAssets1[i].Debt
		userAssets[testUserAssets1[i].Index].Loan = testUserAssets1[i].Loan
		userAssets[testUserAssets1[i].Index].Margin = testUserAssets1[i].Margin
		userAssets[testUserAssets1[i].Index].PortfolioMargin = testUserAssets1[i].PortfolioMargin
	}

	expectHash = ComputeAssetsCommitmentForTest(userAssets)

	hasher.Reset()
	actualHash = ComputeUserAssetsCommitment(&hasher, testUserAssets1)
	if string(expectHash) != string(actualHash) {
		t.Errorf("not match: %x:%x\n", expectHash, actualHash)
	}

	// case 2 测试所有资产都为0
	userAssets = make([]AccountAsset, AssetCounts)
	for i := 0; i < AssetCounts; i++ {
		userAssets[i].Index = uint16(i)
		userAssets[i].Equity = uint64(i*10 + 1000)
		userAssets[i].Debt = uint64(i*10 + 500)
	}
	expectHash = ComputeAssetsCommitmentForTest(userAssets)
	hasher.Reset()
	actualHash = ComputeUserAssetsCommitment(&hasher, userAssets)
	if string(expectHash) != string(actualHash) {
		t.Errorf("not match: %x:%x\n", expectHash, actualHash)
	}

}

// 测试用户数据集的解析
func TestParseUserDataSet(t *testing.T) {
	// two user files: one has 90 valid accounts and 10 invalid accounts,
	// the other has 80 valid accounts and 20 invalid accounts
	accounts, cexAssetsInfo, _ := ParseUserDataSet("../sampledata")
	// if err != nil {
	// 	t.Errorf("error: %s\n", err.Error())
	// }
	// 2. 验证总用户数量
	totalNum := 0
	for _, v := range accounts {
		totalNum += len(v)
	}
	if totalNum != 170 {
		t.Errorf("error: %d\n", totalNum)
	}

	_ = cexAssetsInfo
	// 3. 测试第一个用户文件
	accounts0, invalidAccountNum, _ := ReadUserDataFromCsvFile("../sampledata/sample_users0.csv", cexAssetsInfo)
	totalNum = 0
	for _, v := range accounts0 {
		totalNum += len(v)
	}
	// 验证有效和无效账户数量
	if invalidAccountNum != 10 {
		t.Errorf("error: %d\n", invalidAccountNum)
	}
	if totalNum != 90 {
		t.Errorf("error: %d\n", totalNum)
	}
	accounts1, invalidAccountNum, _ := ReadUserDataFromCsvFile("../sampledata/sample_users1.csv", cexAssetsInfo)
	totalNum = 0
	for _, v := range accounts1 {
		totalNum += len(v)
	}
	if invalidAccountNum != 20 {
		t.Errorf("error: %d\n", invalidAccountNum)
	}
	if totalNum != 80 {
		t.Errorf("error: %d\n", totalNum)
	}

}

// 测试CEX资产信息文件的解析
func TestParseCexAssetInfoFromFile(t *testing.T) {
	// 1. 打开并读取CSV文件
	cf, err := os.Open("./cex_assets_info.csv")
	if err != nil {
		t.Errorf("error: %s\n", err.Error())
	}
	defer cf.Close()

	// 2. 解析CSV数据
	csvReader := csv.NewReader(cf)
	data, err := csvReader.ReadAll()
	if err != nil {
		t.Error(err.Error())
	}
	data = data[1:]
	// 3. 提取资产索引
	assetIndexes := make([]string, len(data))
	for i, d := range data {
		assetIndexes[i] = d[0]
	}
	fmt.Println("assetIndexes: ", len(assetIndexes))
	// 4. 解析CEX资产信息
	cexAssetsInfo, err := ParseCexAssetInfoFromFile("./cex_assets_info.csv", assetIndexes)
	if err != nil {
		t.Errorf("error: %s\n", err.Error())
	}
	// 5. 验证资产数量
	actualAssetsCount := 0
	for _, v := range cexAssetsInfo {
		if v.Symbol != "reserved" {
			actualAssetsCount++
		}
	}
	if actualAssetsCount != 326 {
		t.Errorf("error: %d\n", actualAssetsCount)
	}
	// 6. 打印抵押率配置示例
	fmt.Println("cexAssetsInfo: ", cexAssetsInfo[0].PortfolioMarginRatios)
}
