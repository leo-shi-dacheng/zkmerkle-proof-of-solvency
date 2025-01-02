package prover

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/binance/zkmerkle-proof-of-solvency/circuit"
	"github.com/binance/zkmerkle-proof-of-solvency/src/prover/config"
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/binance/zkmerkle-proof-of-solvency/src/witness/witness"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/redis/go-redis/v9"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// Prover 结构体定义了零知识证明生成器
type Prover struct {
	witnessModel witness.WitnessModel // 见证数据模型
	proofModel   ProofModel           // 证明数据模型
	redisCli     *redis.Client        // Redis客户端

	VerifyingKey     groth16.VerifyingKey        // 验证密钥
	ProvingKey       groth16.ProvingKey          // 证明密钥
	SessionName      []string                    // 会话名称列表
	AssetsCountTiers []int                       // 资产数量层级
	R1cs             constraint.ConstraintSystem // 约束系统

	CurrentSnarkParamsInUse int    // 当前使用的SNARK参数
	TaskQueueName           string // 任务队列名称
}

// NewProver 创建新的证明生成器实例
func NewProver(config *config.Config) *Prover {
	// 初始化数据库连接
	db, err := gorm.Open(mysql.Open(config.MysqlDataSource))
	if err != nil {
		panic(err.Error())
	}

	// 初始化Redis客户端
	redisCli := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Host,
		Password: config.Redis.Password,
	})
	taskQueueName := "por_batch_task_queue_" + config.DbSuffix

	// 创建Prover实例
	prover := Prover{
		witnessModel:            witness.NewWitnessModel(db, config.DbSuffix),
		proofModel:              NewProofModel(db, config.DbSuffix),
		redisCli:                redisCli,
		SessionName:             config.ZkKeyName,
		AssetsCountTiers:        config.AssetsCountTiers,
		CurrentSnarkParamsInUse: 0,
		TaskQueueName:           taskQueueName,
	}

	// std.RegisterHints()
	solver.RegisterHint(circuit.IntegerDivision)
	return &prover
}

// fetchTasksByRedis 从Redis队列获取任务
func (p *Prover) fetchTasksByRedis() (int, error) {
	var ctx = context.Background()
	// 阻塞式获取任务，超时时间10秒
	batchHeightStr, err := p.redisCli.BRPop(ctx, 10*time.Second, p.TaskQueueName).Result()
	if err != nil {
		return -1, err
	}

	batchHeight, err := strconv.Atoi(batchHeightStr[1])
	if err != nil {
		return -1, err
	}
	return batchHeight, nil
}

// FetchBatchWitness 获取批次见证数据
func (p *Prover) FetchBatchWitness() ([]*witness.BatchWitness, error) {
	// 从Redis获取任务
	batchHeight, err := p.fetchTasksByRedis()
	if err != nil {
		return nil, err
	}

	// Fetch unproved block witness.
	blockWitnesses, err := p.witnessModel.GetAndUpdateBatchesWitnessByHeight(batchHeight, witness.StatusPublished, witness.StatusReceived)
	if err != nil {
		return nil, err
	}
	return blockWitnesses, nil
}

func (p *Prover) FetchBatchWitnessForRerun() ([]*witness.BatchWitness, error) {
	blockWitness, err := p.witnessModel.GetLatestBatchWitnessByStatus(witness.StatusReceived)
	if err == utils.DbErrNotFound {
		blockWitness, err = p.witnessModel.GetLatestBatchWitnessByStatus(witness.StatusPublished)
	}
	if err != nil {
		return nil, err
	}
	blockWitnesses := make([]*witness.BatchWitness, 1)
	blockWitnesses[0] = blockWitness
	return blockWitnesses, nil
}

// Run 运行证明生成器主循环
// 参数:
//   - flag: 是否重新运行标志
func (p *Prover) Run(flag bool) {
	// 创建证明表
	p.proofModel.CreateProofTable()

	// 主循环
	for {
		var batchWitnesses []*witness.BatchWitness
		var err error

		// 根据运行模式获取见证数据
		if !flag {
			// 正常模式：从Redis队列获取任务
			batchWitnesses, err = p.FetchBatchWitness()
			if errors.Is(err, utils.DbErrNotFound) {
				fmt.Println("there is no published status witness in db, so quit")
				fmt.Println("prover run finish...")
				return
			}
			if errors.Is(err, redis.Nil) {
				fmt.Println("There is no task left in task queue")
				fmt.Println("prover run finish...")
				return
			}
			if err != nil {
				fmt.Println("get batch witness failed: ", err.Error())
				time.Sleep(10 * time.Second)
				continue
			}
		} else {
			// 重新运行模式：获取待处理的见证数据
			batchWitnesses, err = p.FetchBatchWitnessForRerun()
			if errors.Is(err, utils.DbErrNotFound) {
				fmt.Println("there is no received status witness in db, so quit")
				fmt.Println("prover rerun finish...")
				return
			}
			if err != nil {
				fmt.Println("something wrong happened, err is ", err.Error())
				return
			}
		}

		// 处理每个批次的见证数据
		for _, batchWitness := range batchWitnesses {
			// 解码见证数据
			witnessForCircuit := utils.DecodeBatchWitness(batchWitness.WitnessData)

			// 准备CEX资产列表承诺和账户树根
			cexAssetListCommitments := make([][]byte, 2)
			cexAssetListCommitments[0] = witnessForCircuit.BeforeCEXAssetsCommitment
			cexAssetListCommitments[1] = witnessForCircuit.AfterCEXAssetsCommitment
			accountTreeRoots := make([][]byte, 2)
			accountTreeRoots[0] = witnessForCircuit.BeforeAccountTreeRoot
			accountTreeRoots[1] = witnessForCircuit.AfterAccountTreeRoot
			cexAssetListCommitmentsSerial, err := json.Marshal(cexAssetListCommitments)
			if err != nil {
				fmt.Println("marshal cex asset list failed: ", err.Error())
				return
			}
			accountTreeRootsSerial, err := json.Marshal(accountTreeRoots)
			if err != nil {
				fmt.Println("marshal account tree root failed: ", err.Error())
				return
			}

			// 生成和验证证明
			proof, assetsCount, err := p.GenerateAndVerifyProof(witnessForCircuit, batchWitness.Height)
			if err != nil {
				fmt.Println("generate and verify proof error:", err.Error())
				return
			}

			// 序列化证明数据
			var buf bytes.Buffer
			_, err = proof.WriteRawTo(&buf)
			if err != nil {
				fmt.Println("proof serialize failed")
				return
			}
			proofBytes := buf.Bytes()
			//formateProof, _ := FormatProof(proof, witnessForCircuit.BatchCommitment)
			//proofBytes, err := json.Marshal(formateProof)
			//if err != nil {
			//	fmt.Println("marshal batch proof failed: ", err.Error())
			//	return
			//}

			// Check the existence of block proof.
			_, err = p.proofModel.GetProofByBatchNumber(batchWitness.Height)
			if err == nil {
				fmt.Printf("blockProof of height %d exists\n", batchWitness.Height)
				err = p.witnessModel.UpdateBatchWitnessStatus(batchWitness, witness.StatusFinished)
				if err != nil {
					fmt.Println("update witness error:", err.Error())
				}
				continue
			}

			var row = &Proof{
				ProofInfo:               base64.StdEncoding.EncodeToString(proofBytes),
				BatchNumber:             batchWitness.Height,
				CexAssetListCommitments: string(cexAssetListCommitmentsSerial),
				AccountTreeRoots:        string(accountTreeRootsSerial),
				BatchCommitment:         base64.StdEncoding.EncodeToString(witnessForCircuit.BatchCommitment),
				AssetsCount:             assetsCount,
			}
			err = p.proofModel.CreateProof(row)
			if err != nil {
				fmt.Printf("create blockProof of height %d failed\n", batchWitness.Height)
				return
			}
			err = p.witnessModel.UpdateBatchWitnessStatus(batchWitness, witness.StatusFinished)
			if err != nil {
				fmt.Println("update witness error:", err.Error())
			}
		}
	}
}

func (p *Prover) GenerateAndVerifyProof(
	batchWitness *utils.BatchCreateUserWitness,
	batchNumber int64,
) (proof groth16.Proof, assetsCount int, err error) {
	startTime := time.Now().UnixMilli()
	fmt.Println("begin to generate proof for batch: ", batchNumber)
	circuitWitness, _ := circuit.SetBatchCreateUserCircuitWitness(batchWitness)
	// Lazy load r1cs, proving key and verifying key.
	p.LoadSnarkParamsOnce(len(circuitWitness.CreateUserOps[0].Assets))
	verifyWitness := circuit.NewVerifyBatchCreateUserCircuit(batchWitness.BatchCommitment)
	witness, err := frontend.NewWitness(circuitWitness, ecc.BN254.ScalarField())
	if err != nil {
		return proof, 0, err
	}

	vWitness, err := frontend.NewWitness(verifyWitness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return proof, 0, err
	}
	proof, err = groth16.Prove(p.R1cs, p.ProvingKey, witness)
	if err != nil {
		return proof, 0, err
	}
	endTime := time.Now().UnixMilli()
	fmt.Println("proof generation cost ", endTime-startTime, " ms")

	err = groth16.Verify(proof, p.VerifyingKey, vWitness)
	if err != nil {
		return proof, 0, err
	}
	endTime2 := time.Now().UnixMilli()
	fmt.Println("proof verification cost ", endTime2-endTime, " ms")
	return proof, len(circuitWitness.CreateUserOps[0].Assets), nil
}

// LoadSnarkParamsOnce 加载SNARK参数(仅加载一次)
// 该函数负责加载零知识证明所需的密钥和约束系统
// 包括：R1CS约束系统、证明密钥(pk)和验证密钥(vk)
//
// 参数:
//   - targerAssetsCount: 目标资产数量，用于选择对应的参数文件
//
// 工作流程:
// 1. 检查是否需要重新加载
// 2. 查找对应的参数文件
// 3. 加载R1CS约束系统
// 4. 加载证明密钥
// 5. 加载验证密钥
func (p *Prover) LoadSnarkParamsOnce(targerAssetsCount int) {
	// 1. 检查是否需要重新加载
	// 如果当前已加载的参数与目标资产数量相同，则直接返回
	if targerAssetsCount == p.CurrentSnarkParamsInUse {
		return
	}

	// 2. 查找对应的参数文件索引
	index := -1
	for i, v := range p.AssetsCountTiers {
		if targerAssetsCount == v {
			index = i
			break
		}
	}
	if index == -1 {
		panic("the assets count is not in the config file")
	}

	// 3. 加载R1CS约束系统
	s := time.Now()
	fmt.Println("begin loading r1cs of ", targerAssetsCount, " assets")

	// 创建加载完成通知通道
	loadR1csChan := make(chan bool)

	// 启动GC协程，定期清理内存
	go func() {
		for {
			select {
			case <-loadR1csChan:
				fmt.Println("load r1cs finished...... quit")
				return
			case <-time.After(time.Second * 10):
				runtime.GC() // 每10秒执行一次GC
			}
		}
	}()

	// 初始化R1CS约束系统
	p.R1cs = groth16.NewCS(ecc.BN254)

	// 读取R1CS文件
	r1csFromFile, err := os.ReadFile(p.SessionName[index] + ".r1cs")
	if err != nil {
		panic("r1cs file load error..." + err.Error())
	}

	// 解析R1CS数据
	buf := bytes.NewBuffer(r1csFromFile)
	n, err := p.R1cs.ReadFrom(buf)
	if err != nil {
		panic("r1cs read error..." + err.Error())
	}
	fmt.Println("r1cs read size is ", n)

	// 通知R1CS加载完成
	loadR1csChan <- true
	runtime.GC()
	et := time.Now()
	fmt.Println("finish loading r1cs.... the time cost is ", et.Sub(s))

	// 4. 加载证明密钥(Proving Key)
	fmt.Println("begin loading proving key of ", targerAssetsCount, " assets")
	s = time.Now()

	// 读取证明密钥文件
	pkFromFile, err := os.ReadFile(p.SessionName[index] + ".pk")
	if err != nil {
		panic("provingKey file load error:" + err.Error())
	}

	// 解析证明密钥数据
	buf = bytes.NewBuffer(pkFromFile)
	p.ProvingKey = groth16.NewProvingKey(ecc.BN254)
	n, err = p.ProvingKey.UnsafeReadFrom(buf)
	if err != nil {
		panic("provingKey loading error:" + err.Error())
	}
	fmt.Println("proving key read size is ", n)
	et = time.Now()
	fmt.Println("finish loading proving key... the time cost is ", et.Sub(s))

	// 5. 加载验证密钥(Verifying Key)
	fmt.Println("begin loading verifying key of ", targerAssetsCount, " assets")
	s = time.Now()

	// 读取验证密钥文件
	vkFromFile, err := os.ReadFile(p.SessionName[index] + ".vk")
	if err != nil {
		panic("verifyingKey file load error:" + err.Error())
	}

	// 解析验证密钥数据
	buf = bytes.NewBuffer(vkFromFile)
	p.VerifyingKey = groth16.NewVerifyingKey(ecc.BN254)
	n, err = p.VerifyingKey.ReadFrom(buf)
	if err != nil {
		panic("verifyingKey loading error:" + err.Error())
	}
	fmt.Println("verifying key read size is ", n)
	et = time.Now()
	fmt.Println("finish loading verifying key.. the time cost is ", et.Sub(s))

	// 更新当前使用的参数
	p.CurrentSnarkParamsInUse = targerAssetsCount
}
