package bootstrap

import (
	"encoding/json"
	"fmt"

	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/request"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"github.com/hashicorp/go-version"
)

// InitApplication 初始化应用常量
func InitApplication() {
	fmt.Print(`
   ___ _                 _                    
  / __\ | ___  _   _  __| |_ __ _____   _____ 
 / /  | |/ _ \| | | |/ _ | '__/ _ \ \ / / _ \	
/ /___| | (_) | |_| | (_| | | |  __/\ V /  __/
\____/|_|\___/ \__,_|\__,_|_|  \___| \_/ \___|

   V` + conf.BackendVersion + `  Commit #` + conf.LastCommit + `  Pro=` + conf.IsPro + `
================================================

`)

	fmt.Print(`
  _    _ ______ _____ _      ______         _____ _      ____  _    _ _____  
 | |  | |  ____|_   _| |    |  ____|       / ____| |    / __ \| |  | |  __ \ 
 | |  | | |__    | | | |    | |__         | |    | |   | |  | | |  | | |  | |
 | |  | |  __|   | | | |    |  __|        | |    | |   | |  | | |  | | |  | |
 | |__| | |     _| |_| |____| |____       | |____| |___| |__| | |__| | |__| |
  \____/|_|    |_____|______|______|       \_____|______\____/ \____/|_____/ 

   V1.0.0
================================================

`)

	go CheckUpdate()
}

type GitHubRelease struct {
	URL  string `json:"html_url"`
	Name string `json:"name"`
	Tag  string `json:"tag_name"`
}

// CheckUpdate 检查更新
func CheckUpdate() {
	client := request.HTTPClient{}
	res, err := client.Request("GET", "https://api.github.com/repos/cloudreve/cloudreve/releases", nil).GetResponse()
	if err != nil {
		util.Log().Warning("更新检查失败, %s", err)
		return
	}

	var list []GitHubRelease
	if err := json.Unmarshal([]byte(res), &list); err != nil {
		util.Log().Warning("更新检查失败, %s", err)
		return
	}

	if len(list) > 0 {
		present, err1 := version.NewVersion(conf.BackendVersion)
		latest, err2 := version.NewVersion(list[0].Tag)
		if err1 == nil && err2 == nil && latest.GreaterThan(present) {
			util.Log().Info("有新的版本 [%s] 可用，下载：%s", list[0].Name, list[0].URL)
		}
	}

}
