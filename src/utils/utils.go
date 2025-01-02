package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"github.com/klauspost/compress/s2"
	"github.com/shopspring/decimal"
)

// ConvertTierRatiosToBytes 将分层抵押率配置转换为字节数组
// 每两层抵押率配置打包成一个字节数组，用于优化存储和计算
// 参数:
//   - tiersRatio: 分层抵押率配置数组
//
// 返回:
//   - [][]byte: 打包后的字节数组
func ConvertTierRatiosToBytes(tiersRatio []TierRatio) [][]byte {
	res := make([][]byte, 0, len(tiersRatio)/2)
	// 临时计算变量
	resBigInt := new(big.Int).SetUint64(0)
	aBigInt := new(big.Int).SetUint64(0)
	bBigInt := new(big.Int).SetUint64(0)
	cBigInt := new(big.Int).SetUint64(0)
	dBigInt := new(big.Int).SetUint64(0)

	// 每两层打包成一个字节数组
	for i := 0; i < len(tiersRatio); i += 2 {
		// 第一层的处理
		aBigInt.SetUint64(uint64(tiersRatio[i].Ratio))
		bBigInt.Set(tiersRatio[i].BoundaryValue)
		bBigInt.Mul(bBigInt, Uint8MaxValueBigInt)
		aBigInt.Add(aBigInt, bBigInt)

		// 第二层的处理
		cBigInt.SetUint64(uint64(tiersRatio[i+1].Ratio))
		cBigInt.Mul(cBigInt, Uint126MaxValueBigInt)
		dBigInt.Set(tiersRatio[i+1].BoundaryValue)
		dBigInt.Mul(dBigInt, Uint134MaxValueBigInt)
		cBigInt.Add(cBigInt, dBigInt)

		// 合并两层的结果
		resBigInt.Add(aBigInt, cBigInt)
		res = append(res, resBigInt.Bytes())
	}
	return res
}

// ConvertAssetInfoToBytes 将资产信息转换为字节数组
// 将CexAssetInfo结构体的各个字段打包成字节数组
// 参数:
//   - value: 要转换的资产信息(CexAssetInfo类型)
//
// 返回:
//   - [][]byte: 打包后的字节数组
func ConvertAssetInfoToBytes(value any) [][]byte {
	switch t := value.(type) {
	case CexAssetInfo:
		res := make([][]byte, 0, 10)
		// 1. 打包总权益、总债务和基准价格
		aBigInt := new(big.Int).SetUint64(t.TotalEquity)
		bBigInt := new(big.Int).SetUint64(t.TotalDebt)
		cBigInt := new(big.Int).SetUint64(t.BasePrice)
		aBigInt.Mul(aBigInt, Uint64MaxValueBigIntSquare)
		bBigInt.Mul(bBigInt, Uint64MaxValueBigInt)
		aBigInt.Add(aBigInt, bBigInt)
		resBigInt := new(big.Int).Add(aBigInt, cBigInt)
		res = append(res, resBigInt.Bytes())

		// 2. 打包三种抵押品数量
		resBigInt.SetUint64(0)
		aBigInt.SetUint64(t.LoanCollateral)
		bBigInt.SetUint64(t.MarginCollateral)
		cBigInt.SetUint64(t.PortfolioMarginCollateral)
		aBigInt.Mul(aBigInt, Uint64MaxValueBigIntSquare)
		bBigInt.Mul(bBigInt, Uint64MaxValueBigInt)
		aBigInt.Add(aBigInt, bBigInt)
		resBigInt.Add(cBigInt, aBigInt)
		res = append(res, resBigInt.Bytes())

		// one tier ratio: boundaryValue take 118 bits, ratio take 8 bits = 126 bits
		// so two tier ratio take 252 bits, can be stored in one circuit Variable
		// 3. 打包三种抵押率配置
		tempRes := ConvertTierRatiosToBytes(t.LoanRatios[:])
		res = append(res, tempRes...)
		tempRes = ConvertTierRatiosToBytes(t.MarginRatios[:])
		res = append(res, tempRes...)
		tempRes = ConvertTierRatiosToBytes(t.PortfolioMarginRatios[:])
		res = append(res, tempRes...)
		return res
	default:
		panic("not supported type")
	}
}

// SelectAssetValue 根据资产索引和标志选择对应的资产值
// 参数:
//   - expectAssetIndex: 期望的资产索引
//   - flag: 选择标志(0:权益,1:债务,2:贷款,3:保证金,4:投资组合保证金)
//   - currentAssetPosition: 当前资产位置
//   - assets: 资产数组
//
// 返回:
//   - *big.Int: 选择的资产值
//   - bool: 是否是最后一个标志
func SelectAssetValue(expectAssetIndex int, flag int, currentAssetPosition int, assets []AccountAsset) (*big.Int, bool) {
	// 边界检查
	if currentAssetPosition >= len(assets) {
		return ZeroBigInt, false
	}

	// 索引检查
	if int(assets[currentAssetPosition].Index) > expectAssetIndex {
		return ZeroBigInt, false
	} else {
		// 根据flag返回不同类型的值
		switch flag {
		case 0:
			return new(big.Int).SetUint64(assets[currentAssetPosition].Equity), false
		case 1:
			return new(big.Int).SetUint64(assets[currentAssetPosition].Debt), false
		case 2:
			return new(big.Int).SetUint64(assets[currentAssetPosition].Loan), false
		case 3:
			return new(big.Int).SetUint64(assets[currentAssetPosition].Margin), false
		default:
			return new(big.Int).SetUint64(assets[currentAssetPosition].PortfolioMargin), true
		}
	}
}

// IsAssetEmpty 检查资产是否为空
// 参数:
//   - ua: 要检查的账户资产
//
// 返回:
//   - bool: 资产是否为空
func IsAssetEmpty(ua *AccountAsset) bool {
	return ua.Debt == 0 && ua.Equity == 0 && ua.Margin == 0 &&
		ua.PortfolioMargin == 0 && ua.Loan == 0
}

// GetNonEmptyAssetsCountOfUser 获取用户非空资产数量
// 参数:
//   - assets: 用户资产数组
//
// 返回:
//   - int: 用户所属的资产分组大小
func GetNonEmptyAssetsCountOfUser(assets []AccountAsset) int {
	count := 0
	for _, v := range assets {
		if !IsAssetEmpty(&v) {
			count += 1
		}
	}
	// 根据资产数量确定目标分组
	for _, v := range AssetCountsTiers {
		if count <= v {
			return v
		}
	}
	return 0
}

// 获取用户资产数量
func GetAssetsCountOfUser(assets []AccountAsset) int {
	count := len(assets)
	targetCounts := 0
	for _, v := range AssetCountsTiers {
		if count <= v {
			targetCounts = v
			break
		}
	}
	return targetCounts
}

// PaddingAccountAssets 填充账户资产数据到目标长度
// 参数:
//   - assets: 原始资产数组
//
// 返回:
//   - []uint64: 填充后的扁平化资产数组
func PaddingAccountAssets(assets []AccountAsset) (paddingFlattenAssets []uint64) {
	targetCounts := GetAssetsCountOfUser(assets)
	if targetCounts < len(assets) {
		fmt.Println("the target counts is ", targetCounts, " the length of assets is ", len(assets))
		panic("the target counts is less than the length of assets")
	}
	numOfAssetsFields := 6
	paddingFlattenAssets = make([]uint64, targetCounts*numOfAssetsFields)

	// 计算需要填充的数量
	paddingCounts := targetCounts - len(assets)
	currentPaddingCounts := 0
	currentAssetIndex := 0
	index := 0
	for i := 0; i < len(assets); i++ {
		if currentPaddingCounts < paddingCounts {
			for j := currentAssetIndex; j < int(assets[i].Index); j++ {
				currentPaddingCounts += 1

				paddingFlattenAssets[index*numOfAssetsFields] = uint64(j)
				index += 1
				if currentPaddingCounts >= paddingCounts {
					break
				}
			}
		}
		paddingFlattenAssets[index*numOfAssetsFields] = uint64(assets[i].Index)
		paddingFlattenAssets[index*numOfAssetsFields+1] = assets[i].Equity
		paddingFlattenAssets[index*numOfAssetsFields+2] = assets[i].Debt
		paddingFlattenAssets[index*numOfAssetsFields+3] = assets[i].Loan
		paddingFlattenAssets[index*numOfAssetsFields+4] = assets[i].Margin
		paddingFlattenAssets[index*numOfAssetsFields+5] = assets[i].PortfolioMargin
		index += 1
		currentAssetIndex = int(assets[i].Index) + 1
	}
	for i := index; i < targetCounts; i++ {
		paddingFlattenAssets[i*numOfAssetsFields] = uint64(currentAssetIndex)
		currentAssetIndex += 1
	}

	return paddingFlattenAssets
}

// ComputeUserAssetsCommitment 计算用户资产的承诺值
// 参数:
//   - hasher: 哈希函数实例
//   - assets: 用户资产数组
//
// 返回:
//   - []byte: 资产承诺值
func ComputeUserAssetsCommitment(hasher *hash.Hash, assets []AccountAsset) []byte {
	(*hasher).Reset()
	paddingFlattenAssets := PaddingAccountAssets(assets)
	targetCounts := GetAssetsCountOfUser(assets)
	numOfAssetsFields := 6
	numOfOneField := 3
	nEles := (targetCounts*numOfAssetsFields + 2) / numOfOneField

	aBigInt := new(big.Int).SetUint64(0)
	bBigInt := new(big.Int).SetUint64(0)
	cBigInt := new(big.Int).SetUint64(0)
	for i := 0; i < nEles; i++ {
		aBigInt.SetUint64(0)
		if i*numOfOneField < len(paddingFlattenAssets) {
			aBigInt.SetUint64(paddingFlattenAssets[i*numOfOneField])
		}
		bBigInt.SetUint64(0)
		if i*numOfOneField+1 < len(paddingFlattenAssets) {
			bBigInt.SetUint64(paddingFlattenAssets[i*numOfOneField+1])
		}
		cBigInt.SetUint64(0)
		if i*numOfOneField+2 < len(paddingFlattenAssets) {
			cBigInt.SetUint64(paddingFlattenAssets[i*numOfOneField+2])
		}

		sumBigIntBytes := new(big.Int).Add(new(big.Int).Add(
			new(big.Int).Mul(aBigInt, Uint64MaxValueBigIntSquare),
			new(big.Int).Mul(bBigInt, Uint64MaxValueBigInt)),
			cBigInt).Bytes()
		(*hasher).Write(sumBigIntBytes)
	}

	return (*hasher).Sum(nil)
}

// ParseUserDataSet 解析用户数据集
// 参数:
//   - dirname: 用户数据集所在的目录
//
// 返回:
//   - map[int][]AccountInfo: 用户数据集
//   - []CexAssetInfo: CEX资产信息
//   - error: 错误信息
func ParseUserDataSet(dirname string) (map[int][]AccountInfo, []CexAssetInfo, error) {
	const CEX_ASSET_INFO_FILE string = "cex_assets_info.csv"
	userFiles, err := os.ReadDir(dirname)
	if err != nil {
		return nil, nil, err
	}
	accountInfo := make(map[int][]AccountInfo)
	var cexAssetInfo []CexAssetInfo

	workersNum := 8
	userFileNames := make([]string, 0)

	type UserParseRes struct {
		accounts      map[int][]AccountInfo
		invalidAccNum int
	}
	results := make([]chan UserParseRes, workersNum)
	for i := 0; i < workersNum; i++ {
		results[i] = make(chan UserParseRes, 1)
	}

	for _, userFile := range userFiles {
		if !strings.Contains(userFile.Name(), ".csv") {
			continue
		}
		if userFile.Name() == CEX_ASSET_INFO_FILE {
			continue
		}

		userFileNames = append(userFileNames, filepath.Join(dirname, userFile.Name()))
	}
	assetIndexes, err := ParseAssetIndexFromUserFile(userFileNames[0])
	if err != nil {
		return nil, nil, err
	}

	cexAssetInfo, err = ParseCexAssetInfoFromFile(filepath.Join(dirname, CEX_ASSET_INFO_FILE), assetIndexes)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < workersNum; i++ {
		go func(workerId int) {
			for j := workerId; j < len(userFileNames); j += workersNum {
				if j >= len(userFileNames) {
					break
				}
				tmpAccountInfo, invalidAccountNum, err := ReadUserDataFromCsvFile(userFileNames[j], cexAssetInfo)
				if err != nil {
					panic(err.Error())
				}
				results[workerId] <- UserParseRes{
					accounts:      tmpAccountInfo,
					invalidAccNum: invalidAccountNum,
				}
			}
		}(i)
	}

	gcQuitChan := make(chan bool)
	go func() {
		for {
			select {
			case <-time.After(time.Second * 10):
				runtime.GC()
			case <-gcQuitChan:
				return
			}
		}
	}()

	quit := make(chan bool)
	totalInvalidAccountNum := 0
	go func() {
		for i := 0; i < len(userFileNames); i++ {
			res := <-results[i%workersNum]
			totalInvalidAccountNum += res.invalidAccNum
			if i != 0 {
				currentAccountIndex := 0
				for _, v := range accountInfo {
					currentAccountIndex += len(v)
				}
				for _, v := range res.accounts {
					for k := 0; k < len(v); k++ {
						v[k].AccountIndex += uint32(currentAccountIndex)
					}
				}
			}
			for k, v := range res.accounts {
				if accountInfo[k] == nil {
					accountInfo[k] = make([]AccountInfo, 0, len(v))
				}
				accountInfo[k] = append(accountInfo[k], v...)
			}
		}
		quit <- true
	}()
	<-quit
	gcQuitChan <- true
	if totalInvalidAccountNum > 0 {
		fmt.Println("the total invalid account number is ", totalInvalidAccountNum)
		return accountInfo, cexAssetInfo, errors.New("invalid account data")
	}
	return accountInfo, cexAssetInfo, nil
}

func SafeAdd(a uint64, b uint64) (c uint64) {
	c = a + b
	if c < a {
		panic("overflow for balance")
	}
	return c
}

// 从用户文件中解析资产索引
func ParseAssetIndexFromUserFile(userFilename string) ([]string, error) {
	f, err := os.Open(userFilename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	csvReader := csv.NewReader(f)
	data, err := csvReader.Read()
	if err != nil {
		return nil, err
	}
	// 3: rn, id, total_net_balance
	// 6: equity_assetA, debt_assetA, assetA, assetA_loan, assetA_margin, assetA_portfolio_margin
	assetCounts := (len(data) - 3) / 6
	cexAssetsList := make([]string, assetCounts)

	for i := 0; i < assetCounts; i++ {
		cexAssetsList[i] = strings.ToLower(data[i*6+4])
	}
	return cexAssetsList, nil
}

// 填充抵押率配置到目标长度
func PaddingTierRatios(tiersRatio []TierRatio) (res [TierCount]TierRatio) {
	if len(tiersRatio) > TierCount {
		panic("the length of tiers ratio is bigger than TierCount")
	}
	for i := 0; i < TierCount; i++ {
		if i < len(tiersRatio) {
			res[i] = tiersRatio[i]
		} else {
			precomputedValue := new(big.Int).SetUint64(0)
			if len(tiersRatio) > 0 {
				precomputedValue.Set(tiersRatio[len(tiersRatio)-1].PrecomputedValue)
			}

			res[i] = TierRatio{
				BoundaryValue:    new(big.Int).Set(MaxTierBoundaryValue),
				Ratio:            0,
				PrecomputedValue: precomputedValue,
			}
		}
	}
	return res
}

func ParseTiersRatioFromStr(tiersRatioEnc string) ([TierCount]TierRatio, error) {
	tiersRatioEnc = strings.Trim(tiersRatioEnc, "[]")
	if len(tiersRatioEnc) == 0 {
		return PaddingTierRatios([]TierRatio{}), nil
	}
	tiersRatioStrs := strings.Split(tiersRatioEnc, ",")
	tiersRatio := make([]TierRatio, 0, 10)
	valueMultiplier := new(big.Int).SetUint64(10000000000000000)
	for i := 0; i < len(tiersRatioStrs); i += 1 {
		tmpTierRatio := strings.Split(strings.Trim(tiersRatioStrs[i], " "), ":")
		rangeValues := strings.Split(tmpTierRatio[0], "-")
		if len(tmpTierRatio) != 2 || len(rangeValues) != 2 {
			return PaddingTierRatios([]TierRatio{}), errors.New("tiers ratio data wrong")
		}
		lowBoundaryValue, err := ConvertFloatStrToUint64(strings.Trim(rangeValues[0], " "), 1)
		if err != nil {
			return PaddingTierRatios([]TierRatio{}), err
		}
		boundaryValue, err := ConvertFloatStrToUint64(strings.Trim(rangeValues[1], " "), 1)
		if err != nil {
			return PaddingTierRatios([]TierRatio{}), err
		}

		ratio, err := ConvertFloatStrToUint64(strings.Trim(tmpTierRatio[1], " "), 1)
		if err != nil {
			return PaddingTierRatios([]TierRatio{}), err
		}

		boundaryValueBigInt := new(big.Int).SetUint64(boundaryValue)
		boundaryValueBigInt.Mul(boundaryValueBigInt, valueMultiplier)
		lowBoundaryValueBigInt := new(big.Int).SetUint64(lowBoundaryValue)
		lowBoundaryValueBigInt.Mul(lowBoundaryValueBigInt, valueMultiplier)

		if boundaryValueBigInt.Cmp(lowBoundaryValueBigInt) < 0 {
			return PaddingTierRatios([]TierRatio{}), errors.New("tiers boundry value data wrong")
		}
		if boundaryValueBigInt.Cmp(MaxTierBoundaryValue) > 0 {
			return PaddingTierRatios([]TierRatio{}), errors.New("tiers boundry value data wrong")
		}
		tiersRatio = append(tiersRatio, TierRatio{
			BoundaryValue: boundaryValueBigInt,
			Ratio:         uint8(ratio),
		})
		if i > 0 && tiersRatio[i].BoundaryValue.Cmp(tiersRatio[i-1].BoundaryValue) <= 0 {
			return PaddingTierRatios([]TierRatio{}), errors.New("tiers boundry value data wrong")
		}
	}
	CalculatePrecomputedValue(tiersRatio)
	return PaddingTierRatios(tiersRatio), nil
}

func CalculatePrecomputedValue(tiersRatio []TierRatio) {
	precomputedValue := new(big.Int).SetUint64(0)
	for i := 0; i < len(tiersRatio); i++ {
		var diffValue *big.Int
		if i == 0 {
			diffValue = new(big.Int).Sub(tiersRatio[i].BoundaryValue, new(big.Int).SetUint64(0))
		} else {
			diffValue = new(big.Int).Sub(tiersRatio[i].BoundaryValue, tiersRatio[i-1].BoundaryValue)
		}
		precomputedValue.Add(precomputedValue, diffValue.Mul(diffValue, new(big.Int).SetUint64(uint64(tiersRatio[i].Ratio))).Div(diffValue, PercentageMultiplier))
		tiersRatio[i].PrecomputedValue = new(big.Int).Set(precomputedValue)
	}
}

func ParseCexAssetInfoFromFile(name string, assetIndexes []string) ([]CexAssetInfo, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	csvReader := csv.NewReader(f)
	data, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}
	cexAssets2Info := make(map[string]CexAssetInfo)
	data = data[1:]
	for i := 0; i < len(data); i++ {
		if len(data[i]) != 5 {
			fmt.Println("cex asset data wrong:", data[i])
			return nil, errors.New("cex asset data wrong")
		}
		tmpCexAssetInfo := CexAssetInfo{
			Symbol: strings.ToLower(data[i][0]),
		}
		multiplier := int64(100000000)
		if AssetTypeForTwoDigits[tmpCexAssetInfo.Symbol] {
			multiplier = 100000000000000
		}
		tmpCexAssetInfo.BasePrice, err = ConvertFloatStrToUint64(data[i][1], multiplier)
		if err != nil {
			fmt.Println("asset data wrong:", data[i][0], err.Error())
			return nil, err
		}
		tmpCexAssetInfo.LoanRatios, err = ParseTiersRatioFromStr(data[i][2])
		if err != nil {
			fmt.Println("parse loan tiers ratio failed:", data[i][2], err.Error())
			return nil, err
		}
		tmpCexAssetInfo.MarginRatios, err = ParseTiersRatioFromStr(data[i][3])
		if err != nil {
			fmt.Println("parse margin tiers ratio failed:", data[i][3], err.Error())
			return nil, err
		}
		tmpCexAssetInfo.PortfolioMarginRatios, err = ParseTiersRatioFromStr(data[i][4])
		if err != nil {
			fmt.Println("parse portfolio margin tiers ratio failed:", data[i][4], err.Error())
			return nil, err
		}

		cexAssets2Info[tmpCexAssetInfo.Symbol] = tmpCexAssetInfo
	}

	cexAssetsInfo := make([]CexAssetInfo, AssetCounts)

	if len(assetIndexes) != len(cexAssets2Info) {
		fmt.Println("the length of asset indexes is not equal to the length of cex assets info")
		return nil, errors.New("cex asset data wrong")
	}
	for i := 0; i < len(assetIndexes); i++ {
		cexAssetsInfo[i] = cexAssets2Info[assetIndexes[i]]
		cexAssetsInfo[i].Index = uint32(i)
	}
	for i := len(assetIndexes); i < AssetCounts; i++ {
		cexAssetsInfo[i] = CexAssetInfo{
			Symbol:                "reserved",
			BasePrice:             0,
			LoanRatios:            PaddingTierRatios([]TierRatio{}),
			MarginRatios:          PaddingTierRatios([]TierRatio{}),
			PortfolioMarginRatios: PaddingTierRatios([]TierRatio{}),
			Index:                 uint32(i),
		}
	}
	return cexAssetsInfo, nil

}

func ReadUserDataFromCsvFile(name string, cexAssetsInfo []CexAssetInfo) (map[int][]AccountInfo, int, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	csvReader := csv.NewReader(f)
	data, err := csvReader.ReadAll()
	if err != nil {
		return nil, 0, err
	}
	accountIndex := 0
	accounts := make(map[int][]AccountInfo)
	// rn, id,
	// equity_assetA, debt_assetA, assetA, assetA_loan, assetA_margin, assetA_portfolio_margin,
	// equity_assetB, debt_assetB, assetB, assetB_loan, assetB_margin, assetA_portfolio_margin,
	// ......
	assetCounts := (len(data[0]) - 3) / 6
	data = data[1:]
	invalidCounts := 0
	for i := 0; i < len(data); i++ {
		invalidAccountFlag := false
		var account AccountInfo
		assets := make([]AccountAsset, 0, 8)
		account.TotalEquity = new(big.Int).SetInt64(0)
		account.TotalDebt = new(big.Int).SetInt64(0)
		account.TotalCollateral = new(big.Int).SetInt64(0)
		// first element of data[i] is ID. we use accountIndex instead
		account.AccountIndex = uint32(accountIndex)
		accountId, err := hex.DecodeString(data[i][1])
		if err != nil || len(accountId) != 32 {
			panic("accountId is invalid: " + data[i][1])
		}
		account.AccountId = new(fr.Element).SetBytes(accountId).Marshal()
		var tmpAsset AccountAsset
		for j := 0; j < assetCounts; j++ {
			multiplier := int64(100000000)
			if AssetTypeForTwoDigits[cexAssetsInfo[j].Symbol] {
				multiplier = 100
			}
			equity, err := ConvertFloatStrToUint64(data[i][j*6+2], multiplier)
			if err != nil {
				fmt.Println("the symbol is ", cexAssetsInfo[j].Symbol)
				fmt.Println("account", data[i][1], "equity data wrong:", err.Error())
				invalidCounts += 1
				invalidAccountFlag = true
				break
			}

			debt, err := ConvertFloatStrToUint64(data[i][j*6+3], multiplier)
			if err != nil {
				fmt.Println("the debt symbol is ", cexAssetsInfo[j].Symbol)
				fmt.Println("account", data[i][1], "debt data wrong:", err.Error())
				invalidCounts += 1
				invalidAccountFlag = true
				break
			}

			loan, err := ConvertFloatStrToUint64(data[i][j*6+5], multiplier)
			if err != nil {
				fmt.Println("the loan symbol is ", cexAssetsInfo[j].Symbol)
				fmt.Println("account", data[i][1], "loan data wrong:", err.Error())
				invalidCounts += 1
				invalidAccountFlag = true
				break
			}

			margin, err := ConvertFloatStrToUint64(data[i][j*6+6], multiplier)
			if err != nil {
				fmt.Println("the margin symbol is ", cexAssetsInfo[j].Symbol)
				fmt.Println("account", data[i][1], "margin data wrong:", err.Error())
				invalidCounts += 1
				invalidAccountFlag = true
				break
			}

			portfolioMargin, err := ConvertFloatStrToUint64(data[i][j*6+7], multiplier)
			if err != nil {
				fmt.Println("the portfolio margin symbol is ", cexAssetsInfo[j].Symbol)
				fmt.Println("account", data[i][1], "portfolio margin data wrong:", err.Error())
				invalidCounts += 1
				invalidAccountFlag = true
				break
			}

			if equity != 0 || debt != 0 {
				tmpAsset.Index = uint16(j)
				tmpAsset.Equity = equity
				tmpAsset.Debt = debt
				tmpAsset.Loan = loan
				tmpAsset.Margin = margin
				tmpAsset.PortfolioMargin = portfolioMargin
				assets = append(assets, tmpAsset)
				assetTotalCollateral := SafeAdd(tmpAsset.Loan, tmpAsset.Margin)
				assetTotalCollateral = SafeAdd(assetTotalCollateral, tmpAsset.PortfolioMargin)
				if assetTotalCollateral > tmpAsset.Equity {
					fmt.Println("account", data[i][1], "data wrong: total collateral is bigger than equity", assetTotalCollateral, tmpAsset.Equity)
					invalidCounts += 1
					invalidAccountFlag = true
					break
				}

				account.TotalEquity = account.TotalEquity.Add(account.TotalEquity,
					new(big.Int).Mul(new(big.Int).SetUint64(tmpAsset.Equity), new(big.Int).SetUint64(cexAssetsInfo[j].BasePrice)))
				account.TotalDebt = account.TotalDebt.Add(account.TotalDebt,
					new(big.Int).Mul(new(big.Int).SetUint64(tmpAsset.Debt), new(big.Int).SetUint64(cexAssetsInfo[j].BasePrice)))

				account.TotalCollateral = account.TotalCollateral.Add(account.TotalCollateral,
					CalculateAssetValueForCollateral(loan, margin, portfolioMargin, &cexAssetsInfo[j]))
			}
		}

		if !invalidAccountFlag {
			account.Assets = assets
			if account.TotalCollateral.Cmp(account.TotalDebt) >= 0 {
				accountIndex += 1
				for p := 0; p < len(AssetCountsTiers); p++ {
					if len(account.Assets) <= AssetCountsTiers[p] {
						if accounts[AssetCountsTiers[p]] == nil {
							accounts[AssetCountsTiers[p]] = make([]AccountInfo, 0, len(data))
						}
						accounts[AssetCountsTiers[p]] = append(accounts[AssetCountsTiers[p]], account)
						break
					}
				}
			} else {
				invalidCounts += 1
				fmt.Println("account", data[i][1], "data wrong: total debt is bigger than collateral:", account.TotalDebt, account.TotalCollateral)
			}
		}
		if i%100000 == 0 {
			runtime.GC()
		}
	}
	fmt.Println("The invalid accounts number is ", invalidCounts)
	validAccountNum := 0
	for _, v := range accounts {
		validAccountNum += len(v)
	}
	fmt.Println("The valid accounts number is ", validAccountNum)
	return accounts, invalidCounts, nil
}

// CalculateAssetValueForCollateral 计算资产的抵押价值
// 参数:
//   - loan: 贷款数量
//   - margin: 保证金数量
//   - portfolioMargin: 投资组合保证金数量
//   - cexAssetInfo: 资产信息
//
// 返回:
//   - *big.Int: 计算后的抵押价值
func CalculateAssetValueForCollateral(loan uint64, margin uint64, portfolioMargin uint64, cexAssetInfo *CexAssetInfo) *big.Int {
	assetPrice := new(big.Int).SetUint64(cexAssetInfo.BasePrice)
	loanValue := new(big.Int).SetUint64(loan)
	loanValue.Mul(loanValue, assetPrice)
	loanValue = CalculateAssetValueViaTiersRatio(loanValue, cexAssetInfo.LoanRatios[:])

	marginValue := new(big.Int).SetUint64(margin)
	marginValue.Mul(marginValue, assetPrice)
	marginValue = CalculateAssetValueViaTiersRatio(marginValue, cexAssetInfo.MarginRatios[:])

	portfolioMarginValue := new(big.Int).SetUint64(portfolioMargin)
	portfolioMarginValue.Mul(portfolioMarginValue, assetPrice)
	portfolioMarginValue = CalculateAssetValueViaTiersRatio(portfolioMarginValue, cexAssetInfo.PortfolioMarginRatios[:])
	return loanValue.Add(loanValue, marginValue).Add(loanValue, portfolioMarginValue)
}

// CalculateAssetValueViaTiersRatio 根据分层抵押率计算资产价值
// 参数:
//   - collateralValue: 抵押品价值
//   - tiersRatio: 分层抵押率配置
//
// 返回:
//   - *big.Int: 计算后的资产价值
func CalculateAssetValueViaTiersRatio(collateralValue *big.Int, tiersRatio []TierRatio) *big.Int {
	if len(tiersRatio) == 0 {
		return ZeroBigInt
	}
	var res *big.Int

	for i := 0; i < len(tiersRatio); i++ {
		if collateralValue.Cmp(tiersRatio[i].BoundaryValue) <= 0 {
			if i != 0 {
				collateralValue.Sub(collateralValue, tiersRatio[i-1].BoundaryValue)
			}
			res = new(big.Int).Mul(collateralValue, new(big.Int).SetUint64(uint64(tiersRatio[i].Ratio)))
			res.Div(res, PercentageMultiplier)
			if i != 0 {
				res.Add(res, tiersRatio[i-1].PrecomputedValue)
			}
			return res
		}
	}
	res = new(big.Int).Set(tiersRatio[len(tiersRatio)-1].PrecomputedValue)
	return res
}

func ConvertFloatStrToUint64(f string, multiplier int64) (uint64, error) {
	if f == "0.0" {
		return 0, nil
	}
	numFloat, err := decimal.NewFromString(f)
	if err != nil {
		return 0, err
	}
	numFloat = numFloat.Mul(decimal.NewFromInt(multiplier))
	numBigInt := numFloat.BigInt()
	if !numBigInt.IsUint64() {
		return 0, errors.New("overflow uint64")
	}
	num := numBigInt.Uint64()
	return num, nil
}

func DecodeBatchWitness(data string) *BatchCreateUserWitness {
	var witnessForCircuit BatchCreateUserWitness
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		fmt.Println("deserialize batch witness failed: ", err.Error())
		return nil
	}
	uncompressedData, err := s2.Decode(nil, b)
	if err != nil {
		fmt.Println("uncompress batch witness failed: ", err.Error())
		return nil
	}
	unserializeBuf := bytes.NewBuffer(uncompressedData)
	dec := gob.NewDecoder(unserializeBuf)
	err = dec.Decode(&witnessForCircuit)
	if err != nil {
		fmt.Println("unmarshal batch witness failed: ", err.Error())
		return nil
	}
	for i := 0; i < len(witnessForCircuit.CreateUserOps); i++ {
		userAssets := make([]AccountAsset, AssetCounts)
		for p := 0; p < AssetCounts; p++ {
			userAssets[p] = AccountAsset{
				Index:           uint16(p),
				Equity:          0,
				Debt:            0,
				Loan:            0,
				Margin:          0,
				PortfolioMargin: 0,
			}
		}
		storeUserAssets := witnessForCircuit.CreateUserOps[i].Assets
		for p := 0; p < len(storeUserAssets); p++ {
			userAssets[storeUserAssets[p].Index] = storeUserAssets[p]
		}
		witnessForCircuit.CreateUserOps[i].Assets = userAssets
	}
	return &witnessForCircuit
}

// AccountInfoToHash 计算账户信息的哈希值
// 参数:
//   - account: 账户信息
//   - hasher: 哈希函数实例
//
// 返回:
//   - []byte: 账户哈希值
func AccountInfoToHash(account *AccountInfo, hasher *hash.Hash) []byte {
	assetCommitment := ComputeUserAssetsCommitment(hasher, account.Assets)
	(*hasher).Reset()
	// compute new account leaf node hash
	accountHash := poseidon.PoseidonBytes(account.AccountId, account.TotalEquity.Bytes(), account.TotalDebt.Bytes(), account.TotalCollateral.Bytes(), assetCommitment)
	return accountHash
}

// RecoverAfterCexAssets 恢复CEX资产状态
// 参数:
//   - witness: 见证数据
func RecoverAfterCexAssets(witness *BatchCreateUserWitness) []CexAssetInfo {
	cexAssets := witness.BeforeCexAssets
	for i := 0; i < len(witness.CreateUserOps); i++ {
		for j := 0; j < len(witness.CreateUserOps[i].Assets); j++ {
			asset := &witness.CreateUserOps[i].Assets[j]
			cexAssets[asset.Index].TotalEquity = SafeAdd(cexAssets[asset.Index].TotalEquity, asset.Equity)
			cexAssets[asset.Index].TotalDebt = SafeAdd(cexAssets[asset.Index].TotalDebt, asset.Debt)
			cexAssets[asset.Index].LoanCollateral = SafeAdd(cexAssets[asset.Index].LoanCollateral, asset.Loan)
			cexAssets[asset.Index].MarginCollateral = SafeAdd(cexAssets[asset.Index].MarginCollateral, asset.Margin)
			cexAssets[asset.Index].PortfolioMarginCollateral = SafeAdd(cexAssets[asset.Index].PortfolioMarginCollateral, asset.PortfolioMargin)
		}
	}
	// sanity check
	hasher := poseidon.NewPoseidon()
	for i := 0; i < len(cexAssets); i++ {
		commitments := ConvertAssetInfoToBytes(cexAssets[i])
		for j := 0; j < len(commitments); j++ {
			hasher.Write(commitments[j])
		}
	}
	cexCommitment := hasher.Sum(nil)
	if string(cexCommitment) != string(witness.AfterCEXAssetsCommitment) {
		panic("after cex commitment verify failed")
	}
	return cexAssets
}

func ComputeCexAssetsCommitment(cexAssetsInfo []CexAssetInfo) []byte {
	hasher := poseidon.NewPoseidon()
	emptyCexAssets := make([]CexAssetInfo, AssetCounts-len(cexAssetsInfo))
	for i := len(cexAssetsInfo); i < AssetCounts; i++ {
		emptyCexAssets[i-len(cexAssetsInfo)] = CexAssetInfo{
			Symbol:                "reserved",
			BasePrice:             0,
			LoanRatios:            PaddingTierRatios([]TierRatio{}),
			MarginRatios:          PaddingTierRatios([]TierRatio{}),
			PortfolioMarginRatios: PaddingTierRatios([]TierRatio{}),
			Index:                 uint32(i),
		}
	}
	cexAssetsInfo = append(cexAssetsInfo, emptyCexAssets...)
	for i := 0; i < len(cexAssetsInfo); i++ {
		commitments := ConvertAssetInfoToBytes(cexAssetsInfo[i])
		for j := 0; j < len(commitments); j++ {
			hasher.Write(commitments[j])
		}
	}
	return hasher.Sum(nil)
}

func PaddingAccounts(accounts []AccountInfo, assetKey int, paddingStartIndex int) (int, []AccountInfo) {
	opsPerBatch := BatchCreateUserOpsCountsTiers[assetKey]
	batchCounts := (len(accounts) + opsPerBatch - 1) / opsPerBatch
	paddingAccountCounts := batchCounts*opsPerBatch - len(accounts)
	for i := 0; i < paddingAccountCounts; i++ {
		assets := make([]AccountAsset, assetKey)
		for j := 0; j < assetKey; j++ {
			assets[j] = AccountAsset{
				Index:           uint16(j),
				Equity:          0,
				Debt:            0,
				Loan:            0,
				Margin:          0,
				PortfolioMargin: 0,
			}
		}
		accounts = append(accounts, AccountInfo{
			AccountIndex:    uint32(paddingStartIndex),
			TotalEquity:     new(big.Int).SetInt64(0),
			TotalDebt:       new(big.Int).SetInt64(0),
			TotalCollateral: new(big.Int).SetInt64(0),
			Assets:          assets,
		})
		paddingStartIndex += 1
	}
	return paddingStartIndex, accounts
}
