package model

import (
	"math/big"

	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"gorm.io/gorm"
)

// 表名前缀
const TableNamePreifx = "userproof"

type (
	// UserProofModel 用户证明数据模型接口
	UserProofModel interface {
		CreateUserProofTable() error                       // 创建用户证明表
		DropUserProofTable() error                         // 删除用户证明表
		CreateUserProofs(rows []UserProof) error           // 批量创建用户证明
		GetUserProofByIndex(id uint32) (*UserProof, error) // 通过账户索引获取用户证明
		GetUserProofById(id string) (*UserProof, error)    // 通过账户ID获取用户证明
		GetLatestAccountIndex() (uint32, error)            // 获取最新账户索引
		GetUserCounts() (int, error)                       // 获取用户总数
	}

	defaultUserProofModel struct {
		table string
		DB    *gorm.DB
	}

	UserProof struct {
		AccountIndex    uint32 `gorm:"index:idx_int,unique"` // 账户索引(唯一索引)
		AccountId       string `gorm:"index:idx_str,unique"` // 账户ID(唯一索引)
		AccountLeafHash string // 账户叶子节点哈希
		TotalEquity     string // 总权益
		TotalDebt       string // 总债务
		TotalCollateral string // 总抵押品
		Assets          string // 资产列表(JSON)
		Proof           string // Merkle证明(JSON)
		Config          string // 配置信息(JSON)
	}

	UserConfig struct {
		AccountIndex    uint32               // 账户索引
		AccountIdHash   string               // 账户ID哈希
		TotalEquity     *big.Int             // 总权益
		TotalDebt       *big.Int             // 总债务
		TotalCollateral *big.Int             // 总抵押品
		Assets          []utils.AccountAsset // 资产列表
		Root            string               // Merkle树根
		Proof           [][]byte             // Merkle证明
	}
)

// TableName 获取表名
func (m *defaultUserProofModel) TableName() string {
	return m.table
}

// NewUserProofModel 创建新的用户证明数据模型
// 参数:
//   - db: 数据库连接
//   - suffix: 表名后缀
//
// 返回:
//   - UserProofModel: 用户证明数据模型接口
func NewUserProofModel(db *gorm.DB, suffix string) UserProofModel {
	return &defaultUserProofModel{
		table: TableNamePreifx + suffix,
		DB:    db,
	}
}

// CreateUserProofTable 创建用户证明表
func (m *defaultUserProofModel) CreateUserProofTable() error {
	return m.DB.Table(m.table).AutoMigrate(UserProof{})
}

// DropUserProofTable 删除用户证明表
func (m *defaultUserProofModel) DropUserProofTable() error {
	return m.DB.Migrator().DropTable(m.table)
}

// CreateUserProofs 批量创建用户证明
// 参数:
//   - rows: 用户证明数组
//
// 返回:
//   - error: 错误信息
func (m *defaultUserProofModel) CreateUserProofs(rows []UserProof) error {
	dbTx := m.DB.Table(m.table).Create(rows)
	if dbTx.Error != nil {
		return dbTx.Error
	}
	return nil
}

// GetUserProofByIndex 通过账户索引获取用户证明
// 参数:
//   - id: 账户索引
//
// 返回:
//   - *UserProof: 用户证明
//   - error: 错误信息
func (m *defaultUserProofModel) GetUserProofByIndex(id uint32) (userproof *UserProof, err error) {
	userproof = &UserProof{}
	dbTx := m.DB.Table(m.table).Where("account_index = ?", id).Find(userproof)
	if dbTx.Error != nil {
		return nil, dbTx.Error
	} else if dbTx.RowsAffected == 0 {
		return nil, utils.DbErrNotFound
	}
	return userproof, nil
}

// GetUserProofById 通过账户ID获取用户证明
// 参数:
//   - id: 账户ID
//
// 返回:
//   - *UserProof: 用户证明
//   - error: 错误信息
func (m *defaultUserProofModel) GetUserProofById(id string) (userproof *UserProof, err error) {
	userproof = &UserProof{}
	dbTx := m.DB.Table(m.table).Where("account_id = ?", id).Find(userproof)
	if dbTx.Error != nil {
		return nil, dbTx.Error
	} else if dbTx.RowsAffected == 0 {
		return nil, utils.DbErrNotFound
	}
	return userproof, nil
}

// GetLatestAccountIndex 获取最新账户索引
// 返回:
//   - uint32: 最新账户索引
//   - error: 错误信息
func (m *defaultUserProofModel) GetLatestAccountIndex() (uint32, error) {
	var row *UserProof
	dbTx := m.DB.Table(m.table).Order("account_index desc").Limit(1).Find(&row)
	if dbTx.Error != nil {
		return 0, dbTx.Error
	} else if dbTx.RowsAffected == 0 {
		return 0, utils.DbErrNotFound
	}
	return row.AccountIndex, nil
}

// GetUserCounts 获取用户总数
// 返回:
//   - int: 用户总数
//   - error: 错误信息
func (m *defaultUserProofModel) GetUserCounts() (int, error) {
	var count int64 = 0
	dbTx := m.DB.Table(m.table).Count(&count)
	if dbTx.Error != nil {
		return 0, dbTx.Error
	}
	return int(count), nil
}
