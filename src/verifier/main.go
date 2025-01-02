package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"sync"

	"github.com/binance/zkmerkle-proof-of-solvency/circuit"
	"github.com/binance/zkmerkle-proof-of-solvency/src/utils"
	"github.com/binance/zkmerkle-proof-of-solvency/src/verifier/config"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/gocarina/gocsv"
)

// LoadVerifyingKey 加载验证密钥
// 参数:
//   - vkFileName: 验证密钥文件名
//
// 返回:
//   - groth16.VerifyingKey: 验证密钥
//   - error: 错误信息
func LoadVerifyingKey(vkFileName string) (groth16.VerifyingKey, error) {
	vkFile, err := os.ReadFile(vkFileName)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(vkFile)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return vk, nil
}

// main 函数实现了两种验证模式:
// 1. 用户证明验证模式(-user): 验证单个用户的资产证明
//   - 验证用户的Merkle树证明
//   - 验证用户资产承诺
//   - 验证账户哈希值
//
// 2. 批量证明验证模式: 验证所有批次的证明
//   - 验证每个批次的零知识证明
//   - 验证CEX资产状态变化
//   - 验证账户树根链
//   - 验证最终状态一致性
//
// 工作流程:
// 用户模式:
//  1. 加载用户配置(user_config.json)
//  2. 验证Merkle树根的有效性
//  3. 解码并验证证明路径
//  4. 计算用户资产承诺(使用Poseidon哈希)
//  5. 计算并验证账户叶子节点哈希
//  6. 执行Merkle证明验证
//
// 批量模式:
//  1. 加载验证器配置(config.json)
//  2. 读取并解析证明CSV文件
//  3. 初始化验证状态:
//     - 空账户树根
//     - CEX资产初始状态
//     - 验证密钥加载
//  4. 多线程并行验证:
//     - 验证每个批次的ZK证明
//     - 验证公共输入的正确性
//     - 验证状态转换的连续性
//  5. 验证最终状态:
//     - 验证最终CEX资产状态
//     - 验证最终账户树根
//
// 安全特性:
// - 密码学验证: 使用零知识证明和Merkle树
// - 状态完整性: 验证状态转换链
// - 并发安全: 使用线程安全的数据结构
// - 错误处理: 严格的错误检查和panic处理
func main() {
	// 解析命令行参数
	userFlag := flag.Bool("user", false, "flag which indicates user proof verification")
	flag.Parse()

	if *userFlag {
		// 用户证明验证模式
		// 1. 加载用户配置
		userConfig := &config.UserConfig{}
		content, err := ioutil.ReadFile("config/user_config.json")
		if err != nil {
			panic(err.Error())
		}
		err = json.Unmarshal(content, userConfig)
		if err != nil {
			panic(err.Error())
		}

		// 2. 验证Merkle树根
		root, err := hex.DecodeString(userConfig.Root)
		if err != nil || len(root) != 32 {
			panic("invalid account tree root")
		}

		// 3. 解码证明路径
		var proof [][]byte
		for i := 0; i < len(userConfig.Proof); i++ {
			p, err := base64.StdEncoding.DecodeString(userConfig.Proof[i])
			if err != nil || len(p) != 32 {
				panic("invalid proof")
			}
			proof = append(proof, p)
		}

		// 4. 计算用户资产承诺
		hasher := poseidon.NewPoseidon()
		assetCommitment := utils.ComputeUserAssetsCommitment(&hasher, userConfig.Assets)
		hasher.Reset()

		// 5. 计算账户叶子节点哈希
		accountIdHash, err := hex.DecodeString(userConfig.AccountIdHash)
		if err != nil || len(accountIdHash) != 32 {
			panic("the AccountIdHash is invalid")
		}
		accountHash := poseidon.PoseidonBytes(accountIdHash,
			userConfig.TotalEquity.Bytes(),
			userConfig.TotalDebt.Bytes(),
			userConfig.TotalCollateral.Bytes(),
			assetCommitment)
		fmt.Printf("merkle leave hash: %x\n", accountHash)

		// 6. 验证Merkle证明
		verifyFlag := utils.VerifyMerkleProof(root, userConfig.AccountIndex, proof, accountHash)
		if verifyFlag {
			fmt.Println("verify pass!!!")
		} else {
			fmt.Println("verify failed...")
		}
	} else {
		// 批量证明验证模式
		// 1. 加载验证器配置
		verifierConfig := &config.Config{}
		content, err := ioutil.ReadFile("config/config.json")
		if err != nil {
			panic(err.Error())
		}
		err = json.Unmarshal(content, verifierConfig)
		if err != nil {
			panic(err.Error())
		}

		// 2. 读取证明文件
		f, err := os.Open(verifierConfig.ProofTable)
		if err != nil {
			panic(err.Error())
		}
		defer f.Close()

		// 3. 解析证明数据
		// index 4: proof_info, index 5: cex_asset_list_commitments
		// index 6: account_tree_roots, index 7: batch_commitment
		// index 8: batch_number
		type Proof struct {
			BatchNumber        int64    `csv:"batch_number"`
			ZkProof            string   `csv:"proof_info"`
			CexAssetCommitment []string `csv:"cex_asset_list_commitments"`
			AccountTreeRoots   []string `csv:"account_tree_roots"`
			BatchCommitment    string   `csv:"batch_commitment"`
			AssetsCount        int      `csv:"assets_count"`
		}
		tmpProofs := []*Proof{}

		err = gocsv.UnmarshalFile(f, &tmpProofs)
		if err != nil {
			panic(err.Error())
		}

		proofs := make([]Proof, len(tmpProofs))
		for i := 0; i < len(tmpProofs); i++ {
			proofs[tmpProofs[i].BatchNumber] = *tmpProofs[i]
		}

		// 4. 初始化验证状态
		prevCexAssetListCommitments := make([][]byte, 2)
		prevAccountTreeRoots := make([][]byte, 2)
		// depth-28 empty account tree root
		emptyAccountTreeRoot, err := hex.DecodeString("08696bfcb563a2ee4dde9e1dbd34f68d3f4643df6e3709cdb1855c9f886240c7")
		if err != nil {
			fmt.Println("wrong empty empty account tree root")
			return
		}
		prevAccountTreeRoots[1] = emptyAccountTreeRoot
		// according to asset price info to compute
		cexAssetsInfo := make([]utils.CexAssetInfo, len(verifierConfig.CexAssetsInfo))
		for i := 0; i < len(verifierConfig.CexAssetsInfo); i++ {
			cexAssetsInfo[verifierConfig.CexAssetsInfo[i].Index] = verifierConfig.CexAssetsInfo[i]
			if verifierConfig.CexAssetsInfo[i].TotalEquity < verifierConfig.CexAssetsInfo[i].TotalDebt {
				fmt.Printf("%s asset equity %d less then debt %d\n", verifierConfig.CexAssetsInfo[i].Symbol, verifierConfig.CexAssetsInfo[i].TotalEquity, verifierConfig.CexAssetsInfo[i].TotalDebt)
				panic("invalid cex asset info")
			}
		}
		emptyCexAssetsInfo := make([]utils.CexAssetInfo, len(cexAssetsInfo))
		copy(emptyCexAssetsInfo, cexAssetsInfo)
		for i := 0; i < len(emptyCexAssetsInfo); i++ {
			emptyCexAssetsInfo[i].TotalDebt = 0
			emptyCexAssetsInfo[i].TotalEquity = 0
			emptyCexAssetsInfo[i].LoanCollateral = 0
			emptyCexAssetsInfo[i].MarginCollateral = 0
			emptyCexAssetsInfo[i].PortfolioMarginCollateral = 0
		}
		emptyCexAssetListCommitment := utils.ComputeCexAssetsCommitment(emptyCexAssetsInfo)
		expectFinalCexAssetsInfoComm := utils.ComputeCexAssetsCommitment(cexAssetsInfo)
		prevCexAssetListCommitments[1] = emptyCexAssetListCommitment
		var finalCexAssetsInfoComm []byte
		var accountTreeRoot []byte

		// 5. 并行验证证明
		workersNum := 16
		if runtime.NumCPU() > workersNum {
			workersNum = runtime.NumCPU()
		}
		averageProofCount := (len(proofs) + workersNum - 1) / workersNum

		type ProofMetaData struct {
			accountTreeRoots        [][]byte
			cexAssetListCommitments [][]byte
		}
		type SafeProofMap struct {
			sync.Mutex
			proofMap map[int]ProofMetaData
		}
		safeProofMap := &SafeProofMap{proofMap: make(map[int]ProofMetaData)}
		var wg sync.WaitGroup
		for i := 0; i < workersNum; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				var vk groth16.VerifyingKey
				currentAssetCountsTier := 0
				startIndex := index * averageProofCount
				endIndex := (index + 1) * averageProofCount
				if endIndex > len(proofs) {
					endIndex = len(proofs)
				}
				for j := startIndex; j < endIndex; j++ {
					batchNumber := int(proofs[j].BatchNumber)
					// first deserialize proof
					proof := groth16.NewProof(ecc.BN254)
					var bufRaw bytes.Buffer
					proofRaw, err := base64.StdEncoding.DecodeString(proofs[j].ZkProof)
					if err != nil {
						fmt.Println("decode proof failed:", batchNumber)
						panic("verify proof " + strconv.Itoa(batchNumber) + " failed")
					}
					bufRaw.Write(proofRaw)
					proof.ReadFrom(&bufRaw)
					// deserialize cex asset list commitment and account tree root
					cexAssetListCommitments := make([][]byte, 2)
					accountTreeRoots := make([][]byte, 2)

					for p := 0; p < len(proofs[j].CexAssetCommitment); p++ {
						cexAssetListCommitments[p], err = base64.StdEncoding.DecodeString(proofs[j].CexAssetCommitment[p])
						if err != nil {
							fmt.Println("decode cex asset commitment failed")
							panic(err.Error())
						}
					}
					for p := 0; p < len(proofs[j].AccountTreeRoots); p++ {
						accountTreeRoots[p], err = base64.StdEncoding.DecodeString(proofs[j].AccountTreeRoots[p])
						if err != nil {
							fmt.Println("decode account tree root failed")
							panic(err.Error())
						}
					}
					// verify the public input is correctly computed by cex asset list and account tree root
					poseidonHasher := poseidon.NewPoseidon()
					poseidonHasher.Write(accountTreeRoots[0])
					poseidonHasher.Write(accountTreeRoots[1])
					poseidonHasher.Write(cexAssetListCommitments[0])
					poseidonHasher.Write(cexAssetListCommitments[1])
					expectHash := poseidonHasher.Sum(nil)
					actualHash, err := base64.StdEncoding.DecodeString(proofs[j].BatchCommitment)
					if err != nil {
						fmt.Println("decode batch commitment failed", batchNumber)
						panic("verify proof " + strconv.Itoa(batchNumber) + " failed")
					}
					if string(expectHash) != string(actualHash) {
						fmt.Println("public input verify failed ", batchNumber)
						fmt.Printf("%x:%x\n", expectHash, actualHash)
						panic("verify proof " + strconv.Itoa(batchNumber) + " failed")
					}
					safeProofMap.Lock()
					safeProofMap.proofMap[int(batchNumber)] = ProofMetaData{accountTreeRoots: accountTreeRoots, cexAssetListCommitments: cexAssetListCommitments}
					safeProofMap.Unlock()
					verifyWitness := circuit.NewVerifyBatchCreateUserCircuit(actualHash)
					vWitness, err := frontend.NewWitness(verifyWitness, ecc.BN254.ScalarField(), frontend.PublicOnly())
					if err != nil {
						panic(err.Error())
					}
					if proofs[j].AssetsCount != currentAssetCountsTier {
						index := -1
						for p := 0; p < len(verifierConfig.AssetsCountTiers); p++ {
							if verifierConfig.AssetsCountTiers[p] == proofs[j].AssetsCount {
								index = p
								break
							}
						}
						if index == -1 {
							panic("invalid asset counts tier")
						}
						vk, err = LoadVerifyingKey(verifierConfig.ZkKeyName[index] + ".vk")
						if err != nil {
							panic(err.Error())
						}
						currentAssetCountsTier = proofs[j].AssetsCount
					}
					err = groth16.Verify(proof, vk, vWitness)
					if err != nil {
						fmt.Println("proof verify failed:", batchNumber, err.Error())
						return
					} else {
						fmt.Println("proof verify success", batchNumber)
					}
				}

			}(i)
		}

		wg.Wait()
		for batchNumber := 0; batchNumber < len(proofs); batchNumber++ {
			proofData, ok := safeProofMap.proofMap[batchNumber]
			if !ok {
				panic("proof data not found: " + strconv.Itoa(batchNumber))
			}
			if string(proofData.accountTreeRoots[0]) != string(prevAccountTreeRoots[1]) {
				panic("account tree root not match: " + strconv.Itoa(batchNumber))
			}
			if string(proofData.cexAssetListCommitments[0]) != string(prevCexAssetListCommitments[1]) {
				panic("cex asset list commitment not match: " + strconv.Itoa(batchNumber))
			}
			prevAccountTreeRoots = proofData.accountTreeRoots
			prevCexAssetListCommitments = proofData.cexAssetListCommitments
			accountTreeRoot = proofData.accountTreeRoots[1]
			finalCexAssetsInfoComm = proofData.cexAssetListCommitments[1]
		}

		// 6. 验证最终状态
		if string(finalCexAssetsInfoComm) != string(expectFinalCexAssetsInfoComm) {
			panic("Final Cex Assets Info Not Match")
		}
		fmt.Printf("account merkle tree root is %x\n", accountTreeRoot)
		fmt.Println("All proofs verify passed!!!")
	}
}
