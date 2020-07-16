package obsutil

import "fmt"

type Config struct {
	Endpoint       string `yaml:"endpoint"`
	Ak             string `yaml:"ak"`
	Sk             string `yaml:"sk"`
	BucketName     string `yaml:"bucketName"`
}

func (config *Config) ToString() string {
	res := fmt.Sprintf("Endpoint: %v ,\n "+
			"Ak: %v ,\n "+
			"Sk: %v ,\n "+
			"BucketName: %v ,\n ",  config.Endpoint, config.Ak,
		config.Sk, config.BucketName)
	return res
}
