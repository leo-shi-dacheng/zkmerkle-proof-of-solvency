package prover

import (
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"gorm.io/gorm"
)

// 表名前缀
const (
	TableNamePrefix = "proof"
)

type (
	// ProofModel 定义证明数据模型接口
	ProofModel interface {
		CreateProofTable() error                                   // 创建证明表
		DropProofTable() error                                     // 删除证明表
		CreateProof(row *Proof) error                              // 创建新的证明记录
		GetProofsBetween(start int64, end int64) ([]*Proof, error) // 获取指定范围内的证明
		GetLatestProof() (p *Proof, err error)                     // 获取最新的证明
		GetLatestConfirmedProof() (p *Proof, err error)            // 获取最新的已确认证明
		GetProofByBatchNumber(height int64) (p *Proof, err error)  // 通过批次号获取证明
		GetProofNumber() (count int64)                             // 获取证明总数
		GetRowCounts() (count int64, err error)                    // 获取行数统计
	}

	// defaultProofModel 默认证明数据模型实现
	defaultProofModel struct {
		table string   // 表名
		DB    *gorm.DB // 数据库连接
	}

	// Proof 证明数据结构
	Proof struct {
		gorm.Model                     // gorm模型基类
		ProofInfo               string // 证明信息(base64编码)
		CexAssetListCommitments string // CEX资产列表承诺
		AccountTreeRoots        string // 账户树根列表
		BatchCommitment         string // 批次承诺
		AssetsCount             int    // 资产数量
		BatchNumber             int64  `gorm:"index:idx_number,unique"` // 批次号(唯一索引)
	}
)

// TableName 获取表名
func (m *defaultProofModel) TableName() string {
	return m.table
}

// NewProofModel 创建新的证明数据模型
// 参数:
//   - db: 数据库连接
//   - suffix: 表名后缀
//
// 返回:
//   - ProofModel: 证明数据模型接口
func NewProofModel(db *gorm.DB, suffix string) ProofModel {
	return &defaultProofModel{
		table: TableNamePrefix + suffix,
		DB:    db,
	}
}

// CreateProofTable 创建证明表
func (m *defaultProofModel) CreateProofTable() error {
	return m.DB.Table(m.table).AutoMigrate(Proof{})
}

// DropProofTable 删除证明表
func (m *defaultProofModel) DropProofTable() error {
	return m.DB.Migrator().DropTable(m.table)
}

// CreateProof 创建新的证明记录
// 参数:
//   - row: 证明数据
//
// 返回:
//   - error: 错误信息
func (m *defaultProofModel) CreateProof(row *Proof) error {
	dbTx := m.DB.Table(m.table).Create(row)
	if dbTx.Error != nil {
		return dbTx.Error
	}
	if dbTx.RowsAffected == 0 {
		return utils.DbErrSqlOperation
	}
	return nil
}

// GetProofsBetween 获取指定范围内的证明
// 参数:
//   - start: 起始批次号
//   - end: 结束批次号
//
// 返回:
//   - []*Proof: 证明数组
//   - error: 错误信息
func (m *defaultProofModel) GetProofsBetween(start int64, end int64) (proofs []*Proof, err error) {
	dbTx := m.DB.Debug().Table(m.table).Where("batch_number >= ? AND batch_number <= ?",
		start,
		end).
		Order("batch_number").
		Find(&proofs)

	if dbTx.Error != nil {
		return proofs, utils.DbErrSqlOperation
	} else if dbTx.RowsAffected == 0 {
		return nil, utils.DbErrNotFound
	}

	return proofs, err
}

// GetLatestProof 获取最新的证明
// 返回:
//   - *Proof: 证明数据
//   - error: 错误信息
func (m *defaultProofModel) GetLatestProof() (p *Proof, err error) {
	var row *Proof
	dbTx := m.DB.Table(m.table).Order("batch_number desc").Limit(1).Find(&row)
	if dbTx.Error != nil {
		return nil, utils.DbErrSqlOperation
	} else if dbTx.RowsAffected == 0 {
		return nil, utils.DbErrNotFound
	}
	return row, nil
}

// GetLatestConfirmedProof 获取最新的已确认证明
// 返回:
//   - *Proof: 证明数据
//   - error: 错误信息
func (m *defaultProofModel) GetLatestConfirmedProof() (p *Proof, err error) {
	var row *Proof
	dbTx := m.DB.Table(m.table).Order("batch_number desc").Limit(1).Find(&row)
	if dbTx.Error != nil {
		return nil, utils.DbErrSqlOperation
	} else if dbTx.RowsAffected == 0 {
		return nil, utils.DbErrNotFound
	}
	return row, nil
}

// GetProofByBatchNumber 通过批次号获取证明
// 参数:
//   - num: 批次号
//
// 返回:
//   - *Proof: 证明数据
//   - error: 错误信息
func (m *defaultProofModel) GetProofByBatchNumber(num int64) (p *Proof, err error) {
	var row *Proof
	dbTx := m.DB.Table(m.table).Where("batch_number = ?", num).Find(&row)
	if dbTx.Error != nil {
		return nil, utils.DbErrSqlOperation
	} else if dbTx.RowsAffected == 0 {
		return nil, utils.DbErrNotFound
	}
	return row, nil
}

// GetProofNumber 获取证明总数
// 返回:
//   - count: 证明总数
func (m *defaultProofModel) GetProofNumber() (count int64) {
	m.DB.Raw("select count(*) from " + m.table).Count(&count)
	return count
}

// GetRowCounts 获取行数统计
// 返回:
//   - count: 行数
//   - error: 错误信息
func (m *defaultProofModel) GetRowCounts() (count int64, err error) {
	dbTx := m.DB.Table(m.table).Count(&count)
	if dbTx.Error != nil {
		return 0, dbTx.Error
	}
	return count, nil
}
