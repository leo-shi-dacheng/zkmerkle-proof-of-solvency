package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"

	"github.com/binance/zkmerkle-proof-of-solvency/src/prover/config"
	"github.com/binance/zkmerkle-proof-of-solvency/src/prover/prover"
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
)

// main 函数实现了零知识证明生成器的主要流程
func main() {
	// 1. 加载配置文件
	proverConfig := &config.Config{}
	content, err := ioutil.ReadFile("config/config.json")
	if err != nil {
		panic(err.Error())
	}
	err = json.Unmarshal(content, proverConfig)
	if err != nil {
		panic(err.Error())
	}

	// 2. 验证配置有效性
	// 确保资产层级数量与对应的ZK密钥名称数量一致
	if len(proverConfig.AssetsCountTiers) != len(proverConfig.ZkKeyName) {
		panic("asset tiers and asset tier names should have the same length")
	}

	// 3. 解析命令行参数
	remotePasswdConfig := flag.String("remote_password_config", "", "fetch password from aws secretsmanager")
	rerun := flag.Bool("rerun", false, "flag which indicates rerun proof generation")
	flag.Parse()

	// 4. 处理远程密码配置
	if *remotePasswdConfig != "" {
		// 从AWS Secrets Manager获取MySQL连接字符串
		s, err := utils.GetMysqlSource(proverConfig.MysqlDataSource, *remotePasswdConfig)
		if err != nil {
			panic(err.Error())
		}
		proverConfig.MysqlDataSource = s
	}

	// 5. 创建并运行证明生成器
	prover := prover.NewProver(proverConfig)
	prover.Run(*rerun)
}
