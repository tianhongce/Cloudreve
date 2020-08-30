package config

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

var CloudreveConfig *Config

type Config struct {
	PreviewUrl       string `yaml:"previewurl"`
}

func (config *Config) ToString() string {
	res := fmt.Sprintf("PreviewUrl: %v ,\n ",  config.PreviewUrl)
	return res
}

func LoadObsConfig(confPath string) (*Config, error) {
	conf := new(Config)
	yamlFile, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Println("配置文件yaml读取失败：", err)
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, conf)
	if err != nil {
		log.Println("配置文件yaml解析失败：", err)
		return nil, err
	}
	return conf, nil
}