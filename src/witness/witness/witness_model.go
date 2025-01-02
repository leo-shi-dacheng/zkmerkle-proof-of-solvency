package witness

import (
	"time"

	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// 状态常量定义
const (
	StatusPublished = iota // 已发布
	StatusReceived         // 已接收
	StatusFinished         // 已完成
)

// 表名前缀
const (
	TableNamePrefix = `witness`
)

// WitnessModel 定义见证数据模型接口
type WitnessModel interface {
	CreateBatchWitnessTable() error                                                                                         // 创建批次见证数据表
	DropBatchWitnessTable() error                                                                                           // 删除批次见证数据表
	GetLatestBatchWitnessHeight() (height int64, err error)                                                                 // 获取最新批次高度
	GetBatchWitnessByHeight(height int64) (witness *BatchWitness, err error)                                                // 按高度获取批次见证数据
	UpdateBatchWitnessStatus(witness *BatchWitness, status int64) error                                                     // 更新批次状态
	GetLatestBatchWitness() (witness *BatchWitness, err error)                                                              // 获取最新批次见证数据
	GetLatestBatchWitnessByStatus(status int64) (witness *BatchWitness, err error)                                          // 按状态获取最新批次
	GetAllBatchHeightsByStatus(status int64, limit int, offset int) (witnessHeights []int64, err error)                     // 按状态获取所有批次高度
	GetAndUpdateBatchesWitnessByStatus(beforeStatus, afterStatus int64, count int32) (witness [](*BatchWitness), err error) // 按状态获取并更新批次
	GetAndUpdateBatchesWitnessByHeight(height int, beforeStatus, afterStatus int64) (witness [](*BatchWitness), err error)  // 按高度获取并更新批次
	CreateBatchWitness(witness []BatchWitness) error                                                                        // 创建批次见证数据
	GetRowCounts() (count []int64, err error)                                                                               // 获取行数统计
}

// defaultWitnessModel 默认见证数据模型实现
type defaultWitnessModel struct {
	table string   // 表名
	DB    *gorm.DB // 数据库连接
}

// BatchWitness 批次见证数据结构
type BatchWitness struct {
	gorm.Model
	Height      int64  `gorm:"index:idx_height,unique"` // 批次高度
	WitnessData string // 见证数据
	Status      int64  `gorm:"index"` // 状态
}

// NewWitnessModel 创建新的见证数据模型
func NewWitnessModel(db *gorm.DB, suffix string) WitnessModel {
	return &defaultWitnessModel{
		table: TableNamePrefix + suffix,
		DB:    db,
	}
}

// TableName 获取表名
func (m *defaultWitnessModel) TableName() string {
	return m.table
}

// CreateBatchWitnessTable 创建批次见证数据表
func (m *defaultWitnessModel) CreateBatchWitnessTable() error {
	return m.DB.Table(m.table).AutoMigrate(BatchWitness{})
}

// DropBatchWitnessTable 删除批次见证数据表
func (m *defaultWitnessModel) DropBatchWitnessTable() error {
	return m.DB.Migrator().DropTable(m.table)
}

// GetLatestBatchWitnessHeight 获取最新批次高度
func (m *defaultWitnessModel) GetLatestBatchWitnessHeight() (batchNumber int64, err error) {
	var height int64
	dbTx := m.DB.Table(m.table).Select("height").Order("height desc").Limit(1).Find(&height)
	if dbTx.Error != nil {
		return 0, utils.DbErrSqlOperation
	} else if dbTx.RowsAffected == 0 {
		return 0, utils.DbErrNotFound
	}
	return height, nil
}

// GetLatestBatchWitness 获取最新批次见证数据
func (m *defaultWitnessModel) GetLatestBatchWitness() (witness *BatchWitness, err error) {
	var height int64
	dbTx := m.DB.Table(m.table).Debug().Select("height").Order("height desc").Limit(1).Find(&height)
	if dbTx.Error != nil {
		return nil, dbTx.Error
	} else if dbTx.RowsAffected == 0 {
		return nil, utils.DbErrNotFound
	}

	return m.GetBatchWitnessByHeight(height)
}

// GetLatestBatchWitnessByStatus 按状态获取最新批次
func (m *defaultWitnessModel) GetLatestBatchWitnessByStatus(status int64) (witness *BatchWitness, err error) {
	dbTx := m.DB.Table(m.table).Unscoped().Where("status = ?", status).Limit(1).Find(&witness)
	if dbTx.Error != nil {
		return nil, utils.DbErrSqlOperation
	} else if dbTx.RowsAffected == 0 {
		return nil, utils.DbErrNotFound
	}
	return witness, nil
}

// GetAndUpdateBatchesWitnessByStatus 按状态获取并更新批次
// 在事务中执行状态更新，确保原子性
// 参数:
//   - beforeStatus: 更新前的状态
//   - afterStatus: 更新后的状态
//   - count: 要处理的批次数量
//
// 返回:
//   - witness: 更新的见证数据数组
//   - err: 错误信息
func (m *defaultWitnessModel) GetAndUpdateBatchesWitnessByStatus(beforeStatus, afterStatus int64, count int32) (witness [](*BatchWitness), err error) {
	// 开启数据库事务
	err = m.DB.Table(m.table).Transaction(func(tx *gorm.DB) error {
		// 查询指定状态的批次数据
		// 使用 FOR UPDATE 锁定选中的行，防止并发更新
		// 按高度升序排序，限制处理数量
		dbTx := tx.Debug().Where("status = ?", beforeStatus).
			Order("height asc").
			Limit(int(count)).
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Find(&witness)

		// 检查查询错误
		if dbTx.Error != nil {
			return dbTx.Error
		}
		// 检查是否有数据
		if dbTx.RowsAffected == 0 {
			return utils.DbErrNotFound
		}

		// 准备更新对象
		updateObject := make(map[string]interface{})

		// 遍历需要更新的见证数据
		for _, w := range witness {
			// 设置新状态
			updateObject["Status"] = afterStatus
			// 更新数据库中的状态
			dbTx := tx.Debug().Where("height = ?", w.Height).Updates(&updateObject)

			// 检查更新错误
			if dbTx.Error != nil {
				return dbTx.Error
			}
		}
		return nil
	})

	return witness, err
}

// GetAndUpdateBatchesWitnessByHeight 按高度获取并更新批次
func (m *defaultWitnessModel) GetAndUpdateBatchesWitnessByHeight(height int, beforeStatus, afterStatus int64) (witness [](*BatchWitness), err error) {
	err = m.DB.Table(m.table).Transaction(func(tx *gorm.DB) error {
		// dbTx := tx.Where("status = ?", beforeStatus).Limit(int(count)).Clauses(clause.Locking{Strength: "UPDATE",  Options: "SKIP LOCKED"}).Find(&witness)
		dbTx := tx.Debug().Where("height = ? and status = ?", height, beforeStatus).Order("height asc").Find(&witness)

		if dbTx.Error != nil {
			return dbTx.Error
		} else if dbTx.RowsAffected == 0 {
			return utils.DbErrNotFound
		}

		updateObject := make(map[string]interface{})
		for _, w := range witness {
			updateObject["Status"] = afterStatus
			dbTx := tx.Debug().Where("height = ?", w.Height).Updates(&updateObject)

			if dbTx.Error != nil {
				return dbTx.Error
			}
		}
		return nil
	})
	return witness, err
}

// GetBatchWitnessByHeight 按高度获取批次见证数据
func (m *defaultWitnessModel) GetBatchWitnessByHeight(height int64) (witness *BatchWitness, err error) {
	dbTx := m.DB.Table(m.table).Where("height = ?", height).Limit(1).Find(&witness)
	if dbTx.Error != nil {
		return nil, dbTx.Error
	} else if dbTx.RowsAffected == 0 {
		return nil, utils.DbErrNotFound
	}
	return witness, nil
}

// CreateBatchWitness 创建批次见证数据
func (m *defaultWitnessModel) CreateBatchWitness(witness []BatchWitness) error {
	//if witness.Height > 1 {
	//	_, err := m.GetBatchWitnessByHeight(witness.Height - 1)
	//	if err != nil {
	//		return fmt.Errorf("previous witness does not exist")
	//	}
	//}

	dbTx := m.DB.Table(m.table).Create(witness)
	if dbTx.Error != nil {
		return dbTx.Error
	}
	return nil
}

// GetAllBatchHeightsByStatus 按状态获取所有批次高度
func (m *defaultWitnessModel) GetAllBatchHeightsByStatus(status int64, limit int, offset int) (witnessHeights []int64, err error) {
	dbTx := m.DB.Table(m.table).Debug().Select("height").Where("status = ?", status).Offset(offset).Limit(limit).Find(&witnessHeights)
	if dbTx.Error != nil {
		return nil, dbTx.Error
	} else if dbTx.RowsAffected == 0 {
		return nil, utils.DbErrNotFound
	}
	return witnessHeights, nil
}

// UpdateBatchWitnessStatus 更新批次状态
func (m *defaultWitnessModel) UpdateBatchWitnessStatus(witness *BatchWitness, status int64) error {
	dbTx := m.DB.Table(m.table).Where("height = ?", witness.Height).Updates(BatchWitness{
		Model: gorm.Model{
			UpdatedAt: time.Now(),
		},
		Status: status,
	})
	return dbTx.Error
}

// GetRowCounts 获取行数统计
func (m *defaultWitnessModel) GetRowCounts() (counts []int64, err error) {
	var count int64
	dbTx := m.DB.Table(m.table).Count(&count)
	if dbTx.Error != nil {
		return nil, dbTx.Error
	}
	counts = append(counts, count)
	var publishedCount int64
	dbTx = m.DB.Table(m.table).Where("status = ?", StatusPublished).Count(&publishedCount)
	if dbTx.Error != nil {
		return nil, dbTx.Error
	}
	counts = append(counts, publishedCount)

	var pendingCount int64
	dbTx = m.DB.Table(m.table).Where("status = ?", StatusReceived).Count(&pendingCount)
	if dbTx.Error != nil {
		return nil, dbTx.Error
	}
	counts = append(counts, pendingCount)

	var finishedCount int64
	dbTx = m.DB.Table(m.table).Where("status = ?", StatusFinished).Count(&finishedCount)
	if dbTx.Error != nil {
		return nil, dbTx.Error
	}
	counts = append(counts, finishedCount)
	return counts, nil
}
