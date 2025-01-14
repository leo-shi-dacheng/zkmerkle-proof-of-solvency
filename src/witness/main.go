package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/binance/zkmerkle-proof-of-solvency/src/witness/config"
	"github.com/binance/zkmerkle-proof-of-solvency/src/witness/witness"
)

func main() {
	remotePasswdConfig := flag.String("remote_password_config", "", "fetch password from aws secretsmanager")
	flag.Parse()
	// 1. 加载配置
	witnessConfig := &config.Config{}
	content, err := ioutil.ReadFile("config/config.json")
	if err != nil {
		panic(err.Error())
	}
	err = json.Unmarshal(content, witnessConfig)
	if err != nil {
		panic(err.Error())
	}
	if *remotePasswdConfig != "" {
		s, err := utils.GetMysqlSource(witnessConfig.MysqlDataSource, *remotePasswdConfig)
		if err != nil {
			panic(err.Error())
		}
		witnessConfig.MysqlDataSource = s
	}
	// 2. 加载用户数据
	accounts, cexAssetsInfo, err := utils.ParseUserDataSet(witnessConfig.UserDataFile)
	if err != nil {
		panic(err.Error())
	}
	// 3. 加载账户树
	accountTree, err := utils.NewAccountTree(witnessConfig.TreeDB.Driver, witnessConfig.TreeDB.Option.Addr)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("account tree init height is ", accountTree.LatestVersion())
	fmt.Printf("account tree root is %x\n", accountTree.Root())

	totalAccountNum := 0
	for k, v := range accounts {
		totalAccountNum += len(v)
		fmt.Println("the asset counts of user is ", k, "total ops number is ", len(v))
	}
	// 4. 创建见证服务
	witnessService := witness.NewWitness(accountTree, uint32(totalAccountNum), accounts, cexAssetsInfo, witnessConfig)
	// 5. 运行见证服务
	witnessService.Run()
	fmt.Println("witness service run finished...")
}
