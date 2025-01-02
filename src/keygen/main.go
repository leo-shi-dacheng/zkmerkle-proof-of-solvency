package main

import (
	"fmt"
	"os"

	"github.com/binance/zkmerkle-proof-of-solvency/circuit"
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/consensys/gnark-crypto/ecc"

	"runtime"
	"time"

	"github.com/consensys/gnark/backend/groth16"

	"strconv"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	// 启动一个后台协程定期执行垃圾回收
	go func() {
		for {
			time.Sleep(time.Second * 10) // 每10秒执行一次
			runtime.GC()                 // 强制执行垃圾回收
		}
	}()

	// 遍历不同用户组的配置(50种资产700用户/组, 500种资产92用户/组)
	for k, v := range utils.BatchCreateUserOpsCountsTiers {
		// 为每个用户组创建新的电路
		// k: 资产数量(50/500)
		// v: 每批次用户数量(700/92)
		circuit := circuit.NewBatchCreateUserCircuit(
			uint32(k),         // 资产数量
			utils.AssetCounts, // 总资产类型数量
			uint32(v),         // 批次用户数量
		)

		// 记录开始时间
		startTime := time.Now()

		// 编译电路生成R1CS约束系统
		oR1cs, err := frontend.Compile(
			ecc.BN254.ScalarField(),              // 使用BN254曲线的标量域
			r1cs.NewBuilder,                      // 使用R1CS构建器
			circuit,                              // 电路实例
			frontend.IgnoreUnconstrainedInputs(), // 忽略未约束的输入
		)
		if err != nil {
			panic(err)
		}

		// 计算并打印编译耗时
		endTime := time.Now()
		fmt.Println("R1CS generation time is ", endTime.Sub(startTime))

		// 打印约束数量
		fmt.Println("batch create user constraints number is ", oR1cs.GetNbConstraints())

		// 生成密钥文件名称 (例如: "zkpor50_700")
		zkKeyName := "zkpor" + strconv.FormatInt(int64(k), 10) + "_" + strconv.FormatInt(int64(v), 10)

		// 创建证明密钥文件(.pk)
		pkFile, err := os.Create(zkKeyName + ".pk")
		if err != nil {
			panic(err)
		}

		// 生成证明密钥和验证密钥
		pk, vk, err := groth16.Setup(oR1cs)
		if err != nil {
			panic(err)
		}

		// 写入证明密钥
		n, err := pk.WriteTo(pkFile)
		if err != nil {
			panic(err)
		}
		fmt.Println("pk size is ", n)

		// 创建验证密钥文件(.vk)
		vkFile, err := os.Create(zkKeyName + ".vk")
		if err != nil {
			panic(err)
		}

		// 写入验证密钥
		n, err = vk.WriteTo(vkFile)
		if err != nil {
			panic(err)
		}
		fmt.Println("vk size is ", n)

		// 创建R1CS约束系统文件(.r1cs)
		r1csFile, _ := os.Create(zkKeyName + ".r1cs")

		// 写入R1CS约束系统
		n, err = oR1cs.WriteTo(r1csFile)
		if err != nil {
			panic(err)
		}
		fmt.Println("r1cs size is ", n)
	}
}
