package witness

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"sync/atomic"
	"time"

	"sync"

	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/binance/zkmerkle-proof-of-solvency/src/witness/config"
	bsmt "github.com/bnb-chain/zkbnb-smt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"github.com/klauspost/compress/s2"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Witness 结构体定义了见证数据生成器
type Witness struct {
	accountTree        bsmt.SparseMerkleTree       // 账户Merkle树
	totalOpsNumber     uint32                      // 总操作数
	witnessModel       WitnessModel                // 数据库模型
	ops                map[int][]utils.AccountInfo // 用户账户信息(按资产数量分组)
	cexAssets          []utils.CexAssetInfo        // CEX资产信息
	db                 *gorm.DB                    // 数据库连接
	ch                 chan BatchWitness           // 批次见证数据通道
	quit               chan int                    // 退出信号通道
	accountHashChan    map[int][]chan []byte       // 账户哈希通道(按资产组分类)
	currentBatchNumber int64                       // 当前批次号
	// 批次号映射
	batchNumberMappingKeys   []int // 资产数量键
	batchNumberMappingValues []int // 对应的批次值
}

// NewWitness 创建新的见证数据生成器
func NewWitness(accountTree bsmt.SparseMerkleTree, totalOpsNumber uint32,
	ops map[int][]utils.AccountInfo, cexAssets []utils.CexAssetInfo,
	config *config.Config) *Witness {
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             60 * time.Second, // Slow SQL threshold
			LogLevel:                  logger.Silent,    // Log level
			IgnoreRecordNotFoundError: true,             // Ignore ErrRecordNotFound error for logger
			Colorful:                  false,            // Disable color
		},
	)
	db, err := gorm.Open(mysql.Open(config.MysqlDataSource), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		panic(err.Error())
	}

	return &Witness{
		accountTree:        accountTree,
		totalOpsNumber:     totalOpsNumber,
		witnessModel:       NewWitnessModel(db, config.DbSuffix),
		ops:                ops,
		cexAssets:          cexAssets,
		ch:                 make(chan BatchWitness, 100),
		quit:               make(chan int, 1),
		currentBatchNumber: 0,
		accountHashChan:    make(map[int][]chan []byte),
	}
}

// Run 执行见证数据生成的主要流程
func (w *Witness) Run() {
	// 1. 初始化和状态恢复
	// 创建见证数据表
	w.witnessModel.CreateBatchWitnessTable()
	// 获取最新的见证数据
	latestWitness, err := w.witnessModel.GetLatestBatchWitness()
	var height int64

	// 处理数据库查询结果
	if err == utils.DbErrNotFound {
		height = -1 // 没有历史数据，从头开始
	}
	if err != nil && err != utils.DbErrNotFound {
		panic(err.Error())
	}
	if err == nil {
		height = latestWitness.Height               // 获取最新高度
		w.cexAssets = w.GetCexAssets(latestWitness) // 恢复CEX资产状态
	}

	// 获取需要处理的总批次数
	batchNumber := w.GetBatchNumber()
	if height == int64(batchNumber)-1 {
		fmt.Println("already generate all accounts witness")
		return
	}
	w.currentBatchNumber = height
	fmt.Println("latest height is ", height)

	// 2. 验证和回滚树状态
	if w.accountTree.LatestVersion() > bsmt.Version(height+1) {
		// 如果树的版本号过高，需要回滚
		rollbackVersion := bsmt.Version(height + 1)
		err = w.accountTree.Rollback(rollbackVersion)
		if err != nil {
			fmt.Println("rollback failed ", rollbackVersion, err.Error())
			panic("rollback failed")
		} else {
			fmt.Printf("rollback to %x\n", w.accountTree.Root())
		}
	} else if w.accountTree.LatestVersion() < bsmt.Version(height+1) {
		panic("account tree version is less than current height")
	}

	// 3. 填充账户数据
	w.PaddingAccounts()

	// 4. 初始化哈希计算器
	poseidonHasher := poseidon.NewPoseidon()

	// 5. 启动数据库写入协程
	go w.WriteBatchWitnessToDB()

	// 6. 初始化账户哈希通道
	for k := range w.ops {
		w.accountHashChan[k] = make([]chan []byte, utils.BatchCreateUserOpsCountsTiers[k])
		for p := 0; p < utils.BatchCreateUserOpsCountsTiers[k]; p++ {
			w.accountHashChan[k][p] = make(chan []byte, 1)
		}
	}

	// 7. 设置并行处理参数
	cpuCores := runtime.NumCPU()
	workersNum := 1
	if cpuCores > 2 {
		workersNum = cpuCores - 2 // 预留2个核心给其他任务
	}

	// 8. 主处理循环
	userOpsPerBatch := 0
	startBatchNum := 0
	recoveredBatchNum := int(height)

	// 遍历每个资产组
	for p, k := range w.batchNumberMappingKeys {
		var wg sync.WaitGroup
		endBatchNum := w.batchNumberMappingValues[p]
		userOpsPerBatch = utils.BatchCreateUserOpsCountsTiers[k]
		averageCount := userOpsPerBatch/workersNum + 1

		// 启动并行工作线程
		for i := 0; i < workersNum; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				// 计算账户哈希
				for j := startBatchNum; j < endBatchNum; j++ {
					if j <= recoveredBatchNum {
						continue // 跳过已处理的批次
					}
					if index*averageCount >= userOpsPerBatch {
						break
					}
					lowAccountIndex := index*averageCount + (j-startBatchNum)*userOpsPerBatch
					highAccountIndex := averageCount + lowAccountIndex
					if highAccountIndex > (j-startBatchNum+1)*userOpsPerBatch {
						highAccountIndex = (j - startBatchNum + 1) * userOpsPerBatch
					}
					currentAccountIndex := (j - startBatchNum) * userOpsPerBatch
					// fmt.Printf("worker num: %d, lowAccountInde: %d, highAccountIndex: %d, current: %d\n", index, lowAccountIndex, highAccountIndex, currentAccountIndex)
					w.ComputeAccountHash(k, uint32(lowAccountIndex), uint32(highAccountIndex), uint32(currentAccountIndex))
				}
			}(i)
		}

		// 处理每个批次
		for i := startBatchNum; i < endBatchNum; i++ {
			if i <= recoveredBatchNum {
				continue // 跳过已处理的批次
			}

			// 创建批次见证数据
			batchCreateUserWit := &utils.BatchCreateUserWitness{
				BeforeAccountTreeRoot: w.accountTree.Root(),
				BeforeCexAssets:       make([]utils.CexAssetInfo, utils.AssetCounts),
				CreateUserOps:         make([]utils.CreateUserOperation, userOpsPerBatch),
			}

			// 计算CEX资产承诺
			copy(batchCreateUserWit.BeforeCexAssets[:], w.cexAssets[:])
			for j := 0; j < len(w.cexAssets); j++ {
				commitments := utils.ConvertAssetInfoToBytes(w.cexAssets[j])
				for p := 0; p < len(commitments); p++ {
					poseidonHasher.Write(commitments[p])
				}
			}
			batchCreateUserWit.BeforeCEXAssetsCommitment = poseidonHasher.Sum(nil)
			poseidonHasher.Reset()

			// 执行用户创建操作
			relativeBatchNum := i - startBatchNum
			for j := relativeBatchNum * userOpsPerBatch; j < (relativeBatchNum+1)*userOpsPerBatch; j++ {
				w.ExecuteBatchCreateUser(k, uint32(j), uint32(relativeBatchNum*userOpsPerBatch), batchCreateUserWit)
			}
			for j := 0; j < len(w.cexAssets); j++ {
				commitments := utils.ConvertAssetInfoToBytes(w.cexAssets[j])
				for p := 0; p < len(commitments); p++ {
					poseidonHasher.Write(commitments[p])
				}
			}
			batchCreateUserWit.AfterCEXAssetsCommitment = poseidonHasher.Sum(nil)
			poseidonHasher.Reset()
			batchCreateUserWit.AfterAccountTreeRoot = w.accountTree.Root()

			// compute batch commitment
			batchCreateUserWit.BatchCommitment = poseidon.PoseidonBytes(batchCreateUserWit.BeforeAccountTreeRoot,
				batchCreateUserWit.AfterAccountTreeRoot,
				batchCreateUserWit.BeforeCEXAssetsCommitment,
				batchCreateUserWit.AfterCEXAssetsCommitment)
			// bz, err := json.Marshal(batchCreateUserWit)
			var serializeBuf bytes.Buffer
			enc := gob.NewEncoder(&serializeBuf)
			err := enc.Encode(batchCreateUserWit)
			if err != nil {
				panic(err.Error())
			}
			// startTime := time.Now()
			buf := serializeBuf.Bytes()
			compressedBuf := s2.Encode(nil, buf)
			// endTime := time.Now()
			// fmt.Println("compress time is ", endTime.Sub(startTime), " len of compressed buf is ", len(buf), len(compressedBuf))
			witness := BatchWitness{
				Height:      int64(i),
				WitnessData: base64.StdEncoding.EncodeToString(compressedBuf),
				Status:      StatusPublished,
			}

			// 提交树状态
			accPrunedVersion := bsmt.Version(atomic.LoadInt64(&w.currentBatchNumber) + 1)
			ver, err := w.accountTree.Commit(&accPrunedVersion)
			if err != nil {
				fmt.Println("ver is ", ver)
				panic(err.Error())
			}
			// fmt.Printf("ver is %d account tree root is %x\n", ver, w.accountTree.Root())
			w.ch <- witness
		}
		wg.Wait()
		startBatchNum = endBatchNum
	}

	// 9. 清理和完成
	close(w.ch) // 关闭写入通道
	<-w.quit    // 等待写入完成

	fmt.Printf("witness run finished, the account tree root is %x\n", w.accountTree.Root())
}

// GetCexAssets 从见证数据中恢复CEX资产状态
func (w *Witness) GetCexAssets(wit *BatchWitness) []utils.CexAssetInfo {
	witness := utils.DecodeBatchWitness(wit.WitnessData)
	if witness == nil {
		panic("decode invalid witness data")
	}
	cexAssetsInfo := utils.RecoverAfterCexAssets(witness)
	fmt.Println("recover cex assets successfully")
	return cexAssetsInfo
}

// WriteBatchWitnessToDB 将批次见证数据写入数据库
func (w *Witness) WriteBatchWitnessToDB() {
	datas := make([]BatchWitness, 1)
	for witness := range w.ch {
		datas[0] = witness
		err := w.witnessModel.CreateBatchWitness(datas)
		if err != nil {
			panic("create batch witness failed " + err.Error())
		}
		atomic.StoreInt64(&w.currentBatchNumber, witness.Height)
		if witness.Height%100 == 0 {
			fmt.Println("save batch ", witness.Height, " to db")
		}
	}
	w.quit <- 0
}

// ComputeAccountHash 计算账户哈希值
func (w *Witness) ComputeAccountHash(key int, accountIndex uint32, highAccountIndex uint32, currentIndex uint32) {
	poseidonHasher := poseidon.NewPoseidon()
	for i := accountIndex; i < highAccountIndex; i++ {
		w.accountHashChan[key][i-currentIndex] <- utils.AccountInfoToHash(&w.ops[key][i], &poseidonHasher)
	}
}

// ExecuteBatchCreateUser 执行批量创建用户操作
func (w *Witness) ExecuteBatchCreateUser(assetKey int, accountIndex uint32, currentAccountIndex uint32, batchCreateUserWit *utils.BatchCreateUserWitness) {
	index := accountIndex - currentAccountIndex
	account := w.ops[assetKey][accountIndex]
	batchCreateUserWit.CreateUserOps[index].BeforeAccountTreeRoot = w.accountTree.Root()
	accountProof, err := w.accountTree.GetProof(uint64(account.AccountIndex))
	if err != nil {
		panic(err.Error())
	}
	copy(batchCreateUserWit.CreateUserOps[index].AccountProof[:], accountProof[:])
	for p := 0; p < len(account.Assets); p++ {
		// update cexAssetInfo
		w.cexAssets[account.Assets[p].Index].TotalEquity = utils.SafeAdd(w.cexAssets[account.Assets[p].Index].TotalEquity, account.Assets[p].Equity)
		w.cexAssets[account.Assets[p].Index].TotalDebt = utils.SafeAdd(w.cexAssets[account.Assets[p].Index].TotalDebt, account.Assets[p].Debt)
		w.cexAssets[account.Assets[p].Index].LoanCollateral = utils.SafeAdd(w.cexAssets[account.Assets[p].Index].LoanCollateral, account.Assets[p].Loan)
		w.cexAssets[account.Assets[p].Index].MarginCollateral = utils.SafeAdd(w.cexAssets[account.Assets[p].Index].MarginCollateral, account.Assets[p].Margin)
		w.cexAssets[account.Assets[p].Index].PortfolioMarginCollateral = utils.SafeAdd(w.cexAssets[account.Assets[p].Index].PortfolioMarginCollateral, account.Assets[p].PortfolioMargin)
	}
	// update account tree
	accountHash := <-w.accountHashChan[assetKey][index]
	err = w.accountTree.Set(uint64(account.AccountIndex), accountHash)
	// fmt.Printf("account index %d, hash: %x\n", account.AccountIndex, accountHash)
	if err != nil {
		panic(err.Error())
	}
	batchCreateUserWit.CreateUserOps[index].AfterAccountTreeRoot = w.accountTree.Root()
	batchCreateUserWit.CreateUserOps[index].AccountIndex = account.AccountIndex
	batchCreateUserWit.CreateUserOps[index].AccountIdHash = account.AccountId
	batchCreateUserWit.CreateUserOps[index].Assets = account.Assets
}

// GetBatchNumber 获取总批次数
func (w *Witness) GetBatchNumber() int {
	b := 0
	keys := make([]int, 0)
	for k := range w.ops {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	w.batchNumberMappingKeys = keys
	w.batchNumberMappingValues = make([]int, len(keys))
	for i, k := range keys {
		opsPerBatch := utils.BatchCreateUserOpsCountsTiers[k]
		b += (len(w.ops[k]) + opsPerBatch - 1) / opsPerBatch
		w.batchNumberMappingValues[i] = b
	}
	return b
}

// PaddingAccounts 填充账户数据
func (w *Witness) PaddingAccounts() {
	keys := make([]int, 0)
	for k := range w.ops {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	paddingStartIndex := int(w.totalOpsNumber)
	for _, k := range keys {
		paddingStartIndex, w.ops[k] = utils.PaddingAccounts(w.ops[k], k, paddingStartIndex)
	}
}
