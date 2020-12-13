package main

import (
	"flag"
	"fmt"
	"github.com/cloudreve/Cloudreve/v3/bootstrap"
	"github.com/cloudreve/Cloudreve/v3/config"
	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"github.com/cloudreve/Cloudreve/v3/routers"
	"log"
)

var (
	isEject    bool
	confPath   string
	scriptName string
)

func init() {
	flag.StringVar(&confPath, "c", util.RelativePath("conf.ini"), "配置文件路径")
	flag.BoolVar(&isEject, "eject", false, "导出内置静态资源")
	flag.StringVar(&scriptName, "database-script", "", "运行内置数据库助手脚本")
	flag.Parse()
	bootstrap.Init(confPath)
}

func main() {
	/**
		config, err := obsutil.LoadObsConfig("./obsconfig.yml")
		if err != nil {
			log.Fatal("读取配置文件失败：", err)
		}
		log.Println("配置文件读取成功")
		fmt.Println(config.ToString())

		obsutil.BucketName = config.BucketName
		obsutil.AK = config.Ak
		obsutil.SK = config.Sk
		obsutil.Endpoint = config.Endpoint

		fmt.Println(obsutil.Endpoint)
		fmt.Println(obsutil.AK)
		fmt.Println(obsutil.SK)
		fmt.Println(obsutil.BucketName)

	**/
	var err error
	config.CloudreveConfig, err = config.LoadObsConfig("./config.yml")
	if err != nil {
		log.Fatal("读取配置文件失败：", err)
	}
	log.Println("配置文件读取成功")
	fmt.Println(config.CloudreveConfig.ToString())

	if isEject {
		// 开始导出内置静态资源文件
		bootstrap.Eject()
		return
	}

	if scriptName != "" {
		// 开始运行助手数据库脚本
		bootstrap.RunScript(scriptName)
		return
	}

	api := routers.InitRouter()

	// 如果启用了SSL
	if conf.SSLConfig.CertPath != "" {
		go func() {
			util.Log().Info("开始监听 %s", conf.SSLConfig.Listen)
			if err := api.RunTLS(conf.SSLConfig.Listen,
				conf.SSLConfig.CertPath, conf.SSLConfig.KeyPath); err != nil {
				util.Log().Error("无法监听[%s]，%s", conf.SSLConfig.Listen, err)
			}
		}()
	}

	// 如果启用了Unix
	if conf.UnixConfig.Listen != "" {
		go func() {
			util.Log().Info("开始监听 %s", conf.UnixConfig.Listen)
			if err := api.RunUnix(conf.UnixConfig.Listen); err != nil {
				util.Log().Error("无法监听[%s]，%s", conf.UnixConfig.Listen, err)
			}
		}()
	}

	util.Log().Info("开始监听 %s", conf.SystemConfig.Listen)
	if err := api.Run(conf.SystemConfig.Listen); err != nil {
		util.Log().Error("无法监听[%s]，%s", conf.SystemConfig.Listen, err)
	}
}
