package obsutil

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

func LoadObsConfig(confPath string) (*Config, error) {
	conf := new(Config)
	yamlFile, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Println("yaml读取失败：", err)
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, conf)
	if err != nil {
		log.Println("yaml解析失败：", err)
		return nil, err
	}
	return conf, nil
}