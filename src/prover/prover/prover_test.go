package prover

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/binance/zkmerkle-proof-of-solvency/src/prover/config"
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/binance/zkmerkle-proof-of-solvency/src/witness/witness"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestMockProver 测试证明生成器的并发处理能力
// 主要测试:
// 1. 数据库操作的正确性
// 2. Redis任务队列的可靠性
// 3. 多线程并发处理的性能
// 4. 状态更新的一致性
func TestMockProver(t *testing.T) {
	fmt.Println("========== 开始测试 TestMockProver ==========")
	fmt.Println("1. 初始化数据库连接...")
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             60 * time.Second,
			LogLevel:                  logger.Silent,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	t.Log("TestWitnessModel")
	dbUri := "zkpos:zkpos@123@tcp(127.0.0.1:3306)/zkpos?parseTime=true"
	fmt.Printf("数据库连接URI: %s\n", dbUri)

	db, err := gorm.Open(mysql.Open(dbUri), &gorm.Config{Logger: newLogger})
	if err != nil {
		fmt.Printf("❌ 数据库连接失败: %s\n", err.Error())
		t.Errorf("error: %s\n", err.Error())
	}
	fmt.Println("✅ 数据库连接成功")

	// 2. 准备测试数据
	fmt.Println("\n2. 准备测试数据...")
	witnessTable := witness.NewWitnessModel(db, "test")
	witnessTable.DropBatchWitnessTable()
	fmt.Println("✅ 删除旧的见证表成功")

	err = witnessTable.CreateBatchWitnessTable()
	if err != nil {
		fmt.Printf("❌ 创建见证表失败: %s\n", err.Error())
		t.Errorf("error: %s\n", err.Error())
	}
	fmt.Println("✅ 创建新的见证表成功")

	fmt.Println("\n3. 生成测试数据...")
	largeArray := bytes.Repeat([]byte{'a'}, 1780)
	fmt.Printf("生成的测试数据大小: %d bytes\n", len(largeArray))

	startTime := time.Now()
	datas := make([]witness.BatchWitness, 100)
	fmt.Println("开始批量插入测试数据(1000批次，每批次100条)...")

	for i := 0; i < 1000; i++ {
		if i%100 == 0 {
			fmt.Printf("正在处理第 %d 批数据...\n", i)
		}
		for j := 0; j < 100; j++ {
			status := witness.StatusPublished
			w := witness.BatchWitness{
				Height:      int64(100*i + j),
				Status:      int64(status),
				WitnessData: string(largeArray),
			}
			datas[j] = w
		}
		err = witnessTable.CreateBatchWitness(datas)
		if err != nil {
			fmt.Printf("❌ 批次 %d 数据插入失败: %s\n", i, err.Error())
			t.Errorf("error: %s\n", err.Error())
		}
	}
	endTime := time.Now()
	fmt.Printf("✅ 数据插入完成，耗时: %v\n", endTime.Sub(startTime))

	fmt.Println("\n4. 初始化Redis任务队列...")
	limit := 1024
	offset := 0
	witessStatusList := []int64{witness.StatusPublished, witness.StatusReceived}
	taskQueueName := "por_batch_task_queue_test"
	ctx := context.Background()

	fmt.Println("连接Redis...")
	redisCli := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
	})
	fmt.Println("✅ Redis连接成功")

	fmt.Println("清空任务队列...")
	_, err = redisCli.Del(ctx, taskQueueName).Result()
	if err == nil {
		fmt.Println("✅ 任务队列清空成功")
	}

	fmt.Println("\n5. 推送任务到Redis...")
	for _, status := range witessStatusList {
		offset = 0
		for {
			witnessHeights, err := witnessTable.GetAllBatchHeightsByStatus(status, limit, offset)
			if err == utils.DbErrNotFound {
				fmt.Printf("状态 %d 的见证数据已全部处理完成\n", status)
				break
			}

			redisPipe := redisCli.Pipeline()
			for _, height := range witnessHeights {
				redisPipe.LPush(ctx, taskQueueName, height)
			}
			_, err = redisPipe.Exec(ctx)
			if err != nil {
				fmt.Printf("❌ Redis推送失败: %s\n", err.Error())
				panic(err.Error())
			} else {
				fmt.Printf("✅ 成功推送 %d 个任务到Redis，当前offset: %d\n", len(witnessHeights), offset)
			}
			offset += len(witnessHeights)
		}
	}
	fmt.Println("✅ 所有任务推送完成")

	fmt.Println("\n6. 验证任务队列长度...")
	taskLen, err := redisCli.LLen(ctx, taskQueueName).Result()
	if err != nil {
		fmt.Printf("❌ 获取队列长度失败: %s\n", err.Error())
		panic(err.Error())
	}
	fmt.Printf("当前任务队列长度: %d\n", taskLen)
	if taskLen != 100000 {
		fmt.Printf("❌ 任务队列长度不正确，期望: 100000，实际: %d\n", taskLen)
		t.Fatal("task queue length is not equal to 100000")
	}
	fmt.Println("✅ 任务队列长度验证通过")

	fmt.Println("\n7. 创建证明生成器...")
	config := &config.Config{
		MysqlDataSource: dbUri,
		DbSuffix:        "test",
		Redis: struct {
			Host     string
			Password string
		}{
			Host: "127.0.0.1:6379",
		},
	}

	p := NewProver(config)
	p.proofModel.DropProofTable()
	fmt.Println("✅ 证明生成器初始化完成")

	fmt.Println("\n8. 启动多线程处理...")
	var wg sync.WaitGroup
	startTime = time.Now()

	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			fmt.Printf("启动工作线程 #%d\n", index)

			prover := NewProver(config)
			prover.proofModel.CreateProofTable()

			processedCount := 0
			for {
				var batchWitnesses []*witness.BatchWitness
				var err error
				batchWitnesses, err = prover.FetchBatchWitness()

				if errors.Is(err, utils.DbErrNotFound) {
					fmt.Printf("线程 #%d: 没有待处理的见证数据，退出\n", index)
					fmt.Printf("线程 #%d: 共处理 %d 条数据\n", index, processedCount)
					return
				}
				if errors.Is(err, redis.Nil) {
					fmt.Printf("线程 #%d: 任务队列为空，退出\n", index)
					fmt.Printf("线程 #%d: 共处理 %d 条数据\n", index, processedCount)
					return
				}
				if err != nil {
					fmt.Printf("线程 #%d: 获取见证数据失败: %s\n", index, err.Error())
					time.Sleep(10 * time.Second)
					continue
				}

				for _, batchWitness := range batchWitnesses {
					if processedCount%1000 == 0 {
						fmt.Printf("线程 #%d: 已处理 %d 条数据\n", index, processedCount)
					}

					var row = &Proof{
						ProofInfo:               "testproof",
						BatchNumber:             batchWitness.Height,
						CexAssetListCommitments: string("testcexAssetListCommitments"),
						AccountTreeRoots:        string("testaccountTreeRoots"),
						BatchCommitment:         string("testbatchCommitment"),
						AssetsCount:             0,
					}
					err = prover.proofModel.CreateProof(row)
					if err != nil {
						fmt.Printf("❌ 线程 #%d: 创建证明失败，高度 %d: %s\n",
							index, batchWitness.Height, err.Error())
						panic(err.Error())
					}

					err = prover.witnessModel.UpdateBatchWitnessStatus(batchWitness, witness.StatusFinished)
					if err != nil {
						fmt.Printf("❌ 线程 #%d: 更新见证状态失败: %s\n", index, err.Error())
						panic(err.Error())
					}
					processedCount++
				}
			}
		}(i)
	}

	fmt.Println("等待所有线程完成...")
	wg.Wait()
	endTime = time.Now()
	fmt.Printf("✅ 所有线程处理完成，总耗时: %v\n", endTime.Sub(startTime))

	fmt.Println("\n9. 验证处理结果...")
	counts, _ := witnessTable.GetRowCounts()
	fmt.Printf("见证表状态统计: %v\n", counts)
	if counts[1] != 0 || counts[2] != 0 || counts[3] != 100000 {
		fmt.Printf("❌ 见证表状态统计错误: %v\n", counts)
		t.Fatal("get row counts failed")
	}

	proofCount, _ := p.proofModel.GetRowCounts()
	fmt.Printf("证明表总数: %d\n", proofCount)
	if proofCount != 100000 {
		fmt.Printf("❌ 证明表数量错误，期望: 100000，实际: %d\n", proofCount)
		t.Fatal("proof count not equal to 100000")
	}

	fmt.Println("✅ 所有验证通过")
	fmt.Println("========== 测试完成 ==========")
}
