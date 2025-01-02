package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/binance/zkmerkle-proof-of-solvency/src/userproof/config"
	"github.com/binance/zkmerkle-proof-of-solvency/src/userproof/model"
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	bsmt "github.com/bnb-chain/zkbnb-smt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// HandleUserData 处理用户数据，解析用户数据集
// 参数:
//   - userProofConfig: 用户证明配置
//
// 返回:
//   - map[int][]utils.AccountInfo: 按资产数量分组的用户账户信息
func HandleUserData(userProofConfig *config.Config) map[int][]utils.AccountInfo {
	startTime := time.Now().UnixMilli()
	// 解析用户数据集
	accounts, _, err := utils.ParseUserDataSet(userProofConfig.UserDataFile)
	if err != nil {
		panic(err.Error())
	}

	endTime := time.Now().UnixMilli()
	fmt.Println("handle user data cost ", endTime-startTime, " ms")
	return accounts
}

// AccountLeave 账户叶子节点结构
type AccountLeave struct {
	hash  []byte // 账户哈希值
	index uint32 // 账户索引
}

// ComputeAccountRootHash 计算账户树根哈希
// 参数:
//   - userProofConfig: 用户证明配置
func ComputeAccountRootHash(userProofConfig *config.Config) {
	// 1. 创建内存账户树
	accountTree, err := utils.NewAccountTree("memory", "")
	fmt.Printf("empty accountTree root is %x\n", accountTree.Root())
	if err != nil {
		panic(err.Error())
	}

	// 2. 解析用户数据
	accounts, _, err := utils.ParseUserDataSet(userProofConfig.UserDataFile)
	if err != nil {
		panic(err.Error())
	}

	// 3. 计算总账户数并填充数据
	startTime := time.Now().UnixMilli()
	totalAccountCount := 0
	for _, account := range accounts {
		totalAccountCount += len(account)
	}
	paddingStartIndex := totalAccountCount

	// 4. 按资产数量分组处理
	keys := make([]int, 0)
	for k := range accounts {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	// 5. 并行计算账户哈希
	for _, key := range keys {
		account := accounts[key]
		paddingStartIndex, account = utils.PaddingAccounts(account, key, paddingStartIndex)
		totalOpsNumber := len(account)
		fmt.Println("the asset counts of user is ", key, "total ops number is ", totalOpsNumber)

		// 设置并行处理参数
		chs := make(chan AccountLeave, 1000)
		cpuCores := runtime.NumCPU()
		workers := 1
		if cpuCores > 2 {
			workers = cpuCores - 2
		}
		results := make(chan bool, workers)
		averageAccounts := (totalOpsNumber + workers - 1) / workers
		actualWorkers := 0

		// 启动工作线程
		for i := 0; i < workers; i++ {
			srcAccountIndex := i * averageAccounts
			destAccountIndex := (i + 1) * averageAccounts
			if destAccountIndex > totalOpsNumber {
				destAccountIndex = totalOpsNumber
			}
			go CalculateAccountHash(account[srcAccountIndex:destAccountIndex], chs, results)
			if destAccountIndex == totalOpsNumber {
				actualWorkers = i + 1
				break
			}
		}

		// 启动树根计算线程
		quit := make(chan bool, 1)
		go CalculateAccountTreeRoot(chs, &accountTree, quit)

		// 等待所有工作完成
		for i := 0; i < actualWorkers; i++ {
			<-results
		}
		close(chs)
		<-quit
	}

	// 输出结果
	endTime := time.Now().UnixMilli()
	fmt.Println("user account tree generation cost ", endTime-startTime, " ms")
	fmt.Printf("account tree root %x\n", accountTree.Root())
}

// CalculateAccountHash 计算账户哈希值
// 参数:
//   - accounts: 账户信息数组
//   - chs: 账户叶子节点通道
//   - res: 结果通道
func CalculateAccountHash(accounts []utils.AccountInfo, chs chan<- AccountLeave, res chan<- bool) {
	poseidonHasher := poseidon.NewPoseidon()
	for i := 0; i < len(accounts); i++ {
		chs <- AccountLeave{
			hash:  utils.AccountInfoToHash(&accounts[i], &poseidonHasher),
			index: accounts[i].AccountIndex,
		}
	}
	res <- true
}

// CalculateAccountTreeRoot 计算账户树根
// 参数:
//   - accountLeaves: 账户叶子节点通道
//   - accountTree: 账户树指针
//   - quit: 退出通道
func CalculateAccountTreeRoot(accountLeaves <-chan AccountLeave, accountTree *bsmt.SparseMerkleTree, quit chan<- bool) {
	num := 0
	for accountLeaf := range accountLeaves {
		(*accountTree).Set(uint64(accountLeaf.index), accountLeaf.hash)
		num++
		if num%100000 == 0 {
			fmt.Println("for now, already set ", num, " accounts in tree")
		}
	}
	quit <- true
}

// main 主函数，处理用户证明生成
func main() {
	// 命令行参数解析
	memoryTreeFlag := flag.Bool("memory_tree", false, "construct memory merkle tree")
	remotePasswdConfig := flag.String("remote_password_config", "", "fetch password from aws secretsmanager")
	flag.Parse()

	// 加载配置文件
	userProofConfig := &config.Config{}
	content, err := ioutil.ReadFile("config/config.json")
	if err != nil {
		panic(err.Error())
	}
	err = json.Unmarshal(content, userProofConfig)
	if err != nil {
		panic(err.Error())
	}

	// 如果指定了远程密码配置，获取MySQL连接字符串
	if *remotePasswdConfig != "" {
		s, err := utils.GetMysqlSource(userProofConfig.MysqlDataSource, *remotePasswdConfig)
		if err != nil {
			panic(err.Error())
		}
		userProofConfig.MysqlDataSource = s
	}

	// 如果是内存树模式，只计算根哈希后返回
	if *memoryTreeFlag {
		ComputeAccountRootHash(userProofConfig)
		return
	}

	// 创建账户树和处理用户数据
	accountTree, err := utils.NewAccountTree(userProofConfig.TreeDB.Driver, userProofConfig.TreeDB.Option.Addr)
	accountsMap := HandleUserData(userProofConfig)

	// 统计账户信息
	totalAccountCounts := 0
	accountAssetKeys := make([]int, 0)
	for k, accounts := range accountsMap {
		totalAccountCounts += len(accounts)
		accountAssetKeys = append(accountAssetKeys, k)
		fmt.Println("the asset counts of user is ", k, "total ops number is ", len(accounts))
	}
	sort.Ints(accountAssetKeys)
	fmt.Println("total accounts num", totalAccountCounts)

	// 初始化数据库表
	userProofModel := OpenUserProofTable(userProofConfig)
	currentAccountCounts, err := userProofModel.GetUserCounts()
	if err != nil && err != utils.DbErrNotFound {
		panic(err.Error())
	}
	totalCounts := currentAccountCounts

	// 获取账户树根哈希
	accountTreeRoot := hex.EncodeToString(accountTree.Root())

	// 创建通道
	jobs := make(chan Job, 1000)                 // 任务通道
	nums := make(chan int, 1)                    // 计数通道
	results := make(chan *model.UserProof, 1000) // 结果通道

	// 启动工作线程
	for i := 0; i < 1; i++ {
		go worker(jobs, results, nums, accountTreeRoot)
	}

	// 启动数据库写入线程
	quit := make(chan int, 1)
	for i := 0; i < 1; i++ {
		go WriteDB(results, userProofModel, quit, currentAccountCounts)
	}

	// 处理每个资产组的账户
	prevAccountCounts := 0
	for _, k := range accountAssetKeys {
		accounts := accountsMap[k]
		// 跳过已处理的账户
		if currentAccountCounts >= len(accounts)+prevAccountCounts {
			prevAccountCounts = len(accounts) + prevAccountCounts
			continue
		}

		// 为每个账户生成证明
		for i := currentAccountCounts - prevAccountCounts; i < len(accounts); i++ {
			// 获取账户叶子节点和证明
			leaf, err := accountTree.Get(uint64(accounts[i].AccountIndex), nil)
			if err != nil {
				panic(err.Error())
			}
			proof, err := accountTree.GetProof(uint64(accounts[i].AccountIndex))
			if err != nil {
				panic(err.Error())
			}
			// 发送任务
			jobs <- Job{
				account: &accounts[i],
				proof:   proof,
				leaf:    leaf,
			}
		}
		prevAccountCounts += len(accounts)
		currentAccountCounts = prevAccountCounts
	}

	// 关闭任务通道并等待处理完成
	close(jobs)
	for i := 0; i < 1; i++ {
		num := <-nums
		totalCounts += num
		fmt.Println("totalCounts", totalCounts)
	}

	// 验证处理数量
	expectedTotalCounts := 0
	for _, accounts := range accountsMap {
		expectedTotalCounts += len(accounts)
	}
	if totalCounts != expectedTotalCounts {
		fmt.Println("totalCounts actual:expected", totalCounts, expectedTotalCounts)
		panic("mismatch num")
	}

	// 关闭结果通道并等待写入完成
	close(results)
	for i := 0; i < 1; i++ {
		<-quit
	}
	fmt.Println("userproof service run finished...")
}

// WriteDB 将用户证明写入数据库
// 参数:
//   - results: 用户证明结果通道
//   - userProofModel: 用户证明数据模型
//   - quit: 退出通道
//   - currentAccountCounts: 当前账户数量
func WriteDB(results <-chan *model.UserProof, userProofModel model.UserProofModel, quit chan<- int, currentAccountCounts int) {
	index := 0
	proofs := make([]model.UserProof, 100) // 批量写入缓冲
	num := int(currentAccountCounts)

	// 处理每个证明结果
	for proof := range results {
		proofs[index] = *proof
		index += 1
		// 每100个写入一次数据库
		if index%100 == 0 {
			error := userProofModel.CreateUserProofs(proofs)
			if error != nil {
				panic(error.Error())
			}
			num += 100
			if num%100000 == 0 {
				fmt.Println("write ", num, "proof to db")
			}
			index = 0
		}
	}

	// 处理剩余的证明
	proofs = proofs[:index]
	if index > 0 {
		fmt.Println("write ", len(proofs), "proofs to db")
		userProofModel.CreateUserProofs(proofs)
		num += index
	}
	fmt.Println("total write ", num)
	quit <- 0
}

// Job 用户证明任务结构
type Job struct {
	account *utils.AccountInfo // 账户信息
	proof   [][]byte           // Merkle证明
	leaf    []byte             // 叶子节点哈希
}

// worker 处理用户证明任务的工作线程
// 参数:
//   - jobs: 任务通道
//   - results: 结果通道
//   - nums: 计数通道
//   - root: 树根哈希
func worker(jobs <-chan Job, results chan<- *model.UserProof, nums chan<- int, root string) {
	num := 0
	for job := range jobs {
		userProof := ConvertAccount(job.account, job.leaf, job.proof, root)
		results <- userProof
		num += 1
	}
	nums <- num
}

// ConvertAccount 将账户信息转换为用户证明
// 参数:
//   - account: 账户信息
//   - leafHash: 叶子节点哈希
//   - proof: Merkle证明
//   - root: 树根哈希
//
// 返回:
//   - *model.UserProof: 用户证明
func ConvertAccount(account *utils.AccountInfo, leafHash []byte, proof [][]byte, root string) *model.UserProof {
	var userProof model.UserProof
	var userConfig model.UserConfig
	userProof.AccountIndex = account.AccountIndex
	userProof.AccountId = hex.EncodeToString(account.AccountId)
	userProof.AccountLeafHash = hex.EncodeToString(leafHash)
	proofSerial, err := json.Marshal(proof)
	userProof.Proof = string(proofSerial)
	assets, err := json.Marshal(account.Assets)
	if err != nil {
		panic(err.Error())
	}
	userProof.Assets = string(assets)
	userProof.TotalDebt = account.TotalDebt.String()
	userProof.TotalEquity = account.TotalEquity.String()
	userProof.TotalCollateral = account.TotalCollateral.String()

	userConfig.AccountIndex = account.AccountIndex
	userConfig.AccountIdHash = hex.EncodeToString(account.AccountId)
	userConfig.Proof = proof
	userConfig.Root = root
	userConfig.Assets = account.Assets
	userConfig.TotalDebt = account.TotalDebt
	userConfig.TotalEquity = account.TotalEquity
	userConfig.TotalCollateral = account.TotalCollateral
	configSerial, err := json.Marshal(userConfig)
	if err != nil {
		panic(err.Error())
	}
	userProof.Config = string(configSerial)
	return &userProof
}

// OpenUserProofTable 打开用户证明表
// 参数:
//   - userConfig: 用户配置
//
// 返回:
//   - model.UserProofModel: 用户证明数据模型
func OpenUserProofTable(userConfig *config.Config) model.UserProofModel {
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             60 * time.Second, // Slow SQL threshold
			LogLevel:                  logger.Silent,    // Log level
			IgnoreRecordNotFoundError: true,             // Ignore ErrRecordNotFound error for logger
			Colorful:                  false,            // Disable color
		},
	)
	db, err := gorm.Open(mysql.Open(userConfig.MysqlDataSource), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		panic(err.Error())
	}
	userProofTable := model.NewUserProofModel(db, userConfig.DbSuffix)
	userProofTable.CreateUserProofTable()
	return userProofTable
}
