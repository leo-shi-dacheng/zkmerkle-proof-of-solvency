# 1. 项目配置
```sh
# 1. 创建配置文件
mkdir -p config
cp src/verifier/config/config.json config/
cp src/dbtool/config/config.json config/dbtool_config.json

# 2. 修改配置文件
# config/config.json 示例:
{
    "ProofTable": "path/to/proof.csv",
    "ZkKeyName": ["zkkey_1", "zkkey_2"],
    "AssetsCountTiers": [5, 10],
    "CexAssetsInfo": []
}

# 3. 准备数据库
mysql -u root -p
> CREATE DATABASE zkpos;
> CREATE USER 'zkpos'@'localhost' IDENTIFIED BY 'zkpos@123';
> GRANT ALL PRIVILEGES ON zkpos.* TO 'zkpos'@'localhost';
```
# 2. 测试数据准备
```sh
# 准备CEX资产信息
cp src/utils/cex_assets_info.csv config/

# 准备用户配置(用于单用户验证)
cp src/verifier/config/user_config.json config/
```

# 3. 运行顺序
```sh
# 1. 首先运行数据库工具初始化数据库
cd src/dbtool
go run main.go

# 2. 运行见证生成器
cd src/witness
go run main.go

# 3. 运行证明生成器
cd src/prover
go run main.go

# 4. 运行验证器
cd src/verifier
# 验证单个用户
go run main.go -user
# 或验证所有批次
go run main.go
```


go test -v ./...