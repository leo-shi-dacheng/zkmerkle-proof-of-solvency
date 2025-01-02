package utils

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// GetSecretFromAws 从AWS Secrets Manager获取密钥
// 参数:
//   - secretId: AWS密钥ID
//
// 返回:
//   - string: 获取到的密钥值
//   - error: 错误信息
func GetSecretFromAws(secretId string) (string, error) {
	// 设置AWS区域
	region := "ap-northeast-1"

	// 加载AWS配置
	config, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
	)
	if err != nil {
		panic("Couldn't load config!")
	}

	// 创建Secrets Manager客户端
	conn := secretsmanager.NewFromConfig(config)

	// 获取密钥值
	result, err := conn.GetSecretValue(context.TODO(),
		&secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretId),
		},
	)
	if err != nil {
		return "", err
	}

	return *result.SecretString, err
}

// GetMysqlSource 获取MySQL连接字符串
// 注意: 用户名中不能包含":"
//
// 参数:
//   - source: 原始连接字符串模板
//   - secretId: AWS密钥ID(用于获取密码)
//
// 返回:
//   - string: 完整的MySQL连接字符串
//   - error: 错误信息
func GetMysqlSource(source string, secretId string) (string, error) {
	// 从AWS获取密钥
	value, err := GetSecretFromAws(secretId)
	if err != nil {
		return "", err
	}

	// 解析密钥JSON
	var result map[string]string
	err = json.Unmarshal([]byte(value), &result)
	if err != nil {
		panic(err.Error())
	}

	// 获取数据库密码
	passwd := result["pg_password"]

	// 解析原始连接字符串
	// 格式: user:password@tcp(host:port)/dbname
	aIndex := strings.Index(source, ":")    // 用户名后的冒号位置
	bIndex := strings.Index(source, "@tcp") // @tcp的位置

	// 验证格式正确性
	if aIndex == -1 || bIndex == -1 || bIndex <= aIndex {
		return "", errors.New("the source format is wrong")
	}

	// 构建新的连接字符串
	// 将密码插入到用户名和@tcp之间
	newSource := source[:aIndex+1] + passwd + source[bIndex:]
	return newSource, nil
}
