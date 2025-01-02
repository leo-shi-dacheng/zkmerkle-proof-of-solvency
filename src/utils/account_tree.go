package utils

import (
	"hash"
	"time"

	bsmt "github.com/bnb-chain/zkbnb-smt"
	"github.com/bnb-chain/zkbnb-smt/database"
	"github.com/bnb-chain/zkbnb-smt/database/memory"
	"github.com/bnb-chain/zkbnb-smt/database/redis"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
)

var (
	NilAccountHash []byte
)

// NewAccountTree 创建新的账户Merkle树
func NewAccountTree(driver string, addr string) (accountTree bsmt.SparseMerkleTree, err error) {
	// 创建Poseidon哈希函数池
	hasher := bsmt.NewHasherPool(func() hash.Hash {
		return poseidon.NewPoseidon()
	})

	// 根据驱动类型选择数据库
	var db database.TreeDB
	if driver == "memory" {
		//  内存存储,用于测试
		db = memory.NewMemoryDB()
	} else if driver == "redis" {
		//  redis存储,用于生产
		redisOption := &redis.RedisConfig{}
		redisOption.Addr = addr
		redisOption.DialTimeout = 10 * time.Second
		redisOption.ReadTimeout = 10 * time.Second
		redisOption.WriteTimeout = 10 * time.Second
		redisOption.PoolTimeout = 15 * time.Second
		redisOption.IdleTimeout = 5 * time.Minute
		redisOption.PoolSize = 500
		redisOption.MaxRetries = 5
		redisOption.MinRetryBackoff = 8 * time.Millisecond
		redisOption.MaxRetryBackoff = 512 * time.Millisecond
		db, err = redis.New(redisOption)
		if err != nil {
			return nil, err
		}
	}

	// 创建稀疏Merkle树
	accountTree, err = bsmt.NewBNBSparseMerkleTree(hasher, db, AccountTreeDepth, NilAccountHash)
	if err != nil {
		return nil, err
	}
	return accountTree, nil
}

// VerifyMerkleProof 验证Merkle证明
func VerifyMerkleProof(root []byte, accountIndex uint32, proof [][]byte, node []byte) bool {
	// 检查证明长度是否正确
	if len(proof) != AccountTreeDepth {
		return false
	}
	// 创建Poseidon哈希函数
	hasher := poseidon.NewPoseidon()
	// 遍历证明路径
	for i := 0; i < AccountTreeDepth; i++ {
		// 检查当前位是否为0
		bit := accountIndex & (1 << i)
		if bit == 0 {
			hasher.Write(node)
			hasher.Write(proof[i])
		} else {
			hasher.Write(proof[i])
			hasher.Write(node)
		}
		node = hasher.Sum(nil)
		hasher.Reset()
	}
	// 检查计算的节点是否等于根节点
	if string(node) != string(root) {
		return false
	}
	return true
}
