.
├── README.md              # 项目说明文档
├── check_prover_status.py # 检查证明生成状态的Python脚本
├── circuit/                              # 核心电路实现
│   ├── batch_create_user_circuit.go      # 批量创建用户的电路实现
│   ├── batch_create_user_circuit_test.go # 电路测试文件
│   ├── constants.go                      # 电路相关常量定义
│   ├── types.go                          # 电路相关数据类型定义
│   ├── utils.go                          # 电路工具函数
│   └── utils_test.go                     # 工具函数测试文件
├── docs/
│   ├── updated_proof_of_solvency_to_mitigate_dummy_user_attack.md  # 防范虚拟用户攻击的技术文档
│   └── user_merkle_tree.png                                        # 用户Merkle树示意图
└── src/
    ├── dbtool/                           # 数据库工具
    │   ├── config/                       # 配置文件目录
    │   │   ├── config.go                 # 配置解析代码
    │   │   └── config.json              # 配置文件
    │   └── main.go                      # 主程序入口
    
    ├── keygen/                          # 密钥生成服务
    │   └── main.go                      # 密钥生成主程序
    
    ├── prover/                          # 证明生成服务
    │   ├── config/                      # 配置目录
    │   │   ├── config.go                # 配置解析代码
    │   │   └── config.json             # 配置文件
    │   ├── main.go                     # 主程序入口
    │   └── prover/                     # 证明生成核心代码
    │       ├── proof_model.go          # 证明数据模型
    │       ├── prover.go               # 证明生成逻辑
    │       └── prover_test.go          # 测试文件
    
    ├── sampledata/                      # 示例数据目录
    │   ├── cex_assets_info.csv         # 交易所资产信息示例
    │   ├── generate_user_files.py      # 生成用户数据的脚本
    │   ├── sample_data_generation.sh   # 数据生成脚本
    │   ├── sample_users0.csv           # 示例用户数据文件
    │   └── sample_users1.csv           # 示例用户数据文件
    
    ├── userproof/                      # 用户证明服务
    │   ├── config/                     # 配置目录
    │   │   ├── config.go               # 配置解析代码
    │   │   └── config.json            # 配置文件
    │   ├── main.go                    # 主程序入口
    │   └── model/                     # 数据模型
    │       └── userproof_model.go     # 用户证明数据模型
    
    ├── utils/                         # 通用工具包
    │   ├── account_tree.go            # 账户树实现
    │   ├── cex_assets_info.csv       # 交易所资产信息
    │   ├── constants.go              # 常量定义
    │   ├── error_codes.go           # 错误码定义
    │   ├── secret_manager.go        # 密钥管理
    │   ├── types.go                 # 通用数据类型定义
    │   ├── utils.go                 # 工具函数
    │   └── utils_test.go            # 工具函数测试
    
    ├── verifier/                    # 验证服务
    │   ├── config/                  # 配置目录
    │   │   ├── config.go            # 配置解析代码
    │   │   ├── config.json         # 配置文件
    │   │   └── user_config.json    # 用户验证配置
    │   └── main.go                 # 主程序入口
    
    └── witness/                     # 见证数据生成服务
        ├── config/                  # 配置目录
        │   ├── config.go            # 配置解析代码
        │   └── config.json         # 配置文件
        ├── main.go                 # 主程序入口
        └── witness/                # 见证数据核心代码
            ├── witness.go          # 见证数据生成逻辑
            └── witness_model.go    # 见证数据模型