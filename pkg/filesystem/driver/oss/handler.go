package oss

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	model "github.com/HFO4/cloudreve/models"
	obs "github.com/HFO4/cloudreve/obs"
	"github.com/HFO4/cloudreve/pkg/filesystem/fsctx"
	"github.com/HFO4/cloudreve/pkg/filesystem/response"
	"github.com/HFO4/cloudreve/pkg/request"
	"github.com/HFO4/cloudreve/pkg/serializer"
	"unsafe"

	//"github.com/aliyun/aliyun-oss-go-sdk/oss"

	//"github.com/HFO4/cloudreve/pkg/util"
	//"github.com/aliyun/aliyun-oss-go-sdk/oss"
	//"github.com/aliyun/aliyun-oss-go-sdk/sample"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// UploadPolicy 阿里云OSS上传策略
type UploadPolicy struct {
	Expiration string        `json:"expiration"`
	Conditions []interface{} `json:"conditions"`
}

// CallbackPolicy 回调策略
type CallbackPolicy struct {
	CallbackURL      string `json:"callbackUrl"`
	CallbackBody     string `json:"callbackBody"`
	CallbackBodyType string `json:"callbackBodyType"`
}

// Driver 阿里云OSS策略适配器
type Driver struct {
	Policy *model.Policy
	//client     *oss.Client
	//bucket     *oss.Bucket
	client     *obs.ObsClient
	bucket     string //*obs.Bucket
	HTTPClient request.Client
}

type key int

const (
	// VersionID 文件版本标识
	VersionID key = iota
)

// CORS 创建跨域策略
func (handler *Driver) CORS() error {
	// 初始化客户端
	if err := handler.InitOSSClient(); err != nil {
		return err
	}

	input := &obs.SetBucketCorsInput{}
	input.Bucket = "test-abc"
	input.CorsRules = []obs.CorsRule{{
		AllowedOrigin: []string{"*"},
		AllowedMethod: []string{
			"GET",
			"POST",
			"PUT",
			"DELETE",
			"HEAD",
		},
		ExposeHeader:  []string{},
		AllowedHeader: []string{"*"},
		MaxAgeSeconds: 3600,
	},}

	_, err := handler.client.SetBucketCors(input)
	return err

	/*oss
	return handler.client.SetBucketCORS(handler.Policy.BucketName, []oss.CORSRule{
		{
			AllowedOrigin: []string{"*"},
			AllowedMethod: []string{
				"GET",
				"POST",
				"PUT",
				"DELETE",
				"HEAD",
			},
			ExposeHeader:  []string{},
			AllowedHeader: []string{"*"},
			MaxAgeSeconds: 3600,
		},
	})
	*/
}

// InitOSSClient 初始化OSS鉴权客户端
func (handler *Driver) InitOSSClient() error {
	fmt.Println("InitOSSClient 初始化OSS鉴权客户端")
	if handler.Policy == nil {
		return errors.New("存储策略为空")
	}

	if handler.client == nil {
		// 初始化客户端
		fmt.Println("obsobsobs")
		fmt.Printf("endpoit: %v, ak: %v, sk: %v\n", handler.Policy.Server, handler.Policy.AccessKey, handler.Policy.SecretKey)
		//client, err := oss.New(handler.Policy.Server, handler.Policy.AccessKey, handler.Policy.SecretKey)
		//obsClient, err := obs.New(handler.Policy.AccessKey, handler.Policy.SecretKey, handler.Policy.Server)
		obsClient, err := obs.New("PAIOWFSCLFH2MA4ZD4LM", "mcMllKTwG5ubrfRASvjZtKoEkgK4ucMMnRBRqupL", "https://obs.cn-north-1.myhuaweicloud.com")
		if err != nil {
			return err
		}
		handler.client = obsClient

		// 初始化存储桶
		//bucket, err := client.Bucket(handler.Policy.BucketName)
		//if err != nil {
		//	return err
		//}
		handler.bucket = "test-abc"//handler.Policy.BucketName

	}

	return nil
}

// List 列出OSS上的文件
func (handler Driver) List(ctx context.Context, base string, recursive bool) ([]response.Object, error) {
	fmt.Println("List 列出OSS上的文件")
	// 初始化客户端
	if err := handler.InitOSSClient(); err != nil {
		return nil, err
	}

	// 列取文件
	base = strings.TrimPrefix(base, "/")
	if base != "" {
		base += "/"
	}

	var (
		delimiter string
		marker    string
		//objects   []oss.ObjectProperties
		objects []obs.Content
		commons   []string
	)
	if !recursive {
		delimiter = "/"
	}

	for{
		input := &obs.ListObjectsInput{}
		input.Bucket = handler.bucket
		input.Marker=marker
		input.Prefix=base
		input.MaxKeys=1000
		input.Delimiter=delimiter

		listObjects, err := handler.client.ListObjects(input)
		if err != nil {
			return nil, err
		}

		objects = append(objects, listObjects.Contents...)
		commons = append(commons, listObjects.CommonPrefixes...)
		marker = listObjects.NextMarker
		if marker == "" {
			break
		}
	}

	//for {
	//	subRes, err := handler.bucket.ListObjects(oss.Marker(marker), oss.Prefix(base),
	//		oss.MaxKeys(1000), oss.Delimiter(delimiter))
	//	if err != nil {
	//		return nil, err
	//	}
	//	objects = append(objects, subRes.Objects...)
	//	commons = append(commons, subRes.CommonPrefixes...)
	//	marker = subRes.NextMarker
	//	if marker == "" {
	//		break
	//	}
	//}

	// 处理列取结果
	res := make([]response.Object, 0, len(objects)+len(commons))
	// 处理目录
	for _, object := range commons {
		rel, err := filepath.Rel(base, object)
		if err != nil {
			continue
		}
		res = append(res, response.Object{
			Name:         path.Base(object),
			RelativePath: filepath.ToSlash(rel),
			Size:         0,
			IsDir:        true,
			LastModify:   time.Now(),
		})
	}
	// 处理文件
	for _, object := range objects {
		rel, err := filepath.Rel(base, object.Key)
		if err != nil {
			continue
		}
		res = append(res, response.Object{
			Name:         path.Base(object.Key),
			Source:       object.Key,
			RelativePath: filepath.ToSlash(rel),
			Size:         uint64(object.Size),
			IsDir:        false,
			LastModify:   object.LastModified,
		})
	}

	return res, nil
}

// Get 获取文件
func (handler Driver) Get(ctx context.Context, path string) (response.RSCloser, error) {
	fmt.Println("Get 获取文件")
	// 通过VersionID禁止缓存
	ctx = context.WithValue(ctx, VersionID, time.Now().UnixNano())

	// 获取文件源地址
	downloadURL, err := handler.Source(
		ctx,
		path,
		url.URL{},
		int64(model.GetIntSetting("preview_timeout", 60)),
		false,
		0,
	)
	if err != nil {
		return nil, err
	}

	// 获取文件数据流
	resp, err := handler.HTTPClient.Request(
		"GET",
		downloadURL,
		nil,
		request.WithContext(ctx),
		request.WithTimeout(time.Duration(0)),
	).CheckHTTPResponse(200).GetRSCloser()
	if err != nil {
		return nil, err
	}

	resp.SetFirstFakeChunk()

	// 尝试自主获取文件大小
	if file, ok := ctx.Value(fsctx.FileModelCtx).(model.File); ok {
		resp.SetContentLength(int64(file.Size))
	}

	return resp, nil
}

// Put 将文件流保存到指定目录
func (handler Driver) Put(ctx context.Context, file io.ReadCloser, dst string, size uint64) error {
	fmt.Println("Put 将文件流保存到指定目录")
	defer file.Close()

	// 初始化客户端
	if err := handler.InitOSSClient(); err != nil {
		return err
	}

	// 凭证有效期
	credentialTTL := model.GetIntSetting("upload_credential_timeout", 3600)

	//options := []oss.Option{
	//	oss.Expires(time.Now().Add(time.Duration(credentialTTL) * time.Second)),
	//}

	// 上传文件
	//err := handler.bucket.PutObject(dst, file, options...)
	//if err != nil {
	//	return err
	//}
	input := &obs.PutObjectInput{}
	input.Bucket = handler.bucket
	input.Key = dst
	//input.Metadata = map[string]string{"meta": "value"}
	input.Body = file
	input.Expires = (time.Now().Add(time.Duration(credentialTTL) * time.Second)).Unix()
	_, err := handler.client.PutObject(input)
	if err != nil {
		return err
	}
	return nil
}

// Delete 删除一个或多个文件，
// 返回未删除的文件
func (handler Driver) Delete(ctx context.Context, files []string) ([]string, error) {
	fmt.Println("Delete 删除一个或多个文件，")
	// 初始化客户端
	if err := handler.InitOSSClient(); err != nil {
		return files, err
	}

	// 删除文件
	//delRes, err := handler.bucket.DeleteObjects(files)


	fmt.Println("删除的文件：",files)
	var deletes []obs.ObjectToDelete

	for _ , v:= range files{
		var del obs.ObjectToDelete
		del.Key=v
		deletes = append(deletes,del)
	}
	input := &obs.DeleteObjectsInput{}
	input.Bucket = handler.bucket
	//TODO: file to objects
	input.Objects=deletes
	delRes, err := handler.client.DeleteObjects(input)

	if err != nil {
		fmt.Println("error:" ,err.Error())
		return files, err
	}

	// 统计未删除的文件
	//failed := util.SliceDifference(files, delRes.DeletedObjects)
	//if len(failed) > 0 {
	//	return failed, errors.New("删除失败")
	//}
	if len(files)!=len(delRes.Deleteds){
		return []string{}, errors.New("删除失败")
	}

	return []string{}, nil
}

// Thumb 获取文件缩略图
func (handler Driver) Thumb(ctx context.Context, path string) (*response.ContentResponse, error) {
	fmt.Println("Thumb 获取文件缩略图")
	// 初始化客户端
	if err := handler.InitOSSClient(); err != nil {
		return nil, err
	}

	var (
		thumbSize = [2]uint{400, 300}
		ok        = false
	)
	if thumbSize, ok = ctx.Value(fsctx.ThumbSizeCtx).([2]uint); !ok {
		return nil, errors.New("无法获取缩略图尺寸设置")
	}

	thumbParam := fmt.Sprintf("image/resize,m_lfit,h_%d,w_%d", thumbSize[1], thumbSize[0])
	ctx = context.WithValue(ctx, fsctx.ThumbSizeCtx, thumbParam)
	//thumbOption := []oss.Option{oss.Process(thumbParam)}
	thumbURL, err := handler.signSourceURL(
		ctx,
		path,
		int64(model.GetIntSetting("preview_timeout", 60)),
		"",
		//thumbOption,
	)
	if err != nil {
		return nil, err
	}

	return &response.ContentResponse{
		Redirect: true,
		URL:      thumbURL,
	}, nil
}

// Source 获取外链URL
func (handler Driver) Source(
	ctx context.Context,
	path string,
	baseURL url.URL,
	ttl int64,
	isDownload bool,
	speed int,
) (string, error) {
	fmt.Println("Source 获取外链URL")
	// 初始化客户端
	if err := handler.InitOSSClient(); err != nil {
		return "", err
	}

	// 尝试从上下文获取文件名
	fileName := ""
	if file, ok := ctx.Value(fsctx.FileModelCtx).(model.File); ok {
		fileName = file.Name
	}
	//
	//// 添加各项设置
	//var signOptions = make([]oss.Option, 0, 2)
	//if isDownload {
	//	signOptions = append(signOptions, oss.ResponseContentDisposition("attachment; filename=\""+url.PathEscape(fileName)+"\""))
	//}
	//if speed > 0 {
	//	// Byte 转换为 bit
	//	speed *= 8
	//
	//	// OSS对速度值有范围限制
	//	if speed < 819200 {
	//		speed = 819200
	//	}
	//	if speed > 838860800 {
	//		speed = 838860800
	//	}
	//	signOptions = append(signOptions, oss.TrafficLimitParam(int64(speed)))
	//}

	return handler.signSourceURL(ctx, path, ttl, fileName)
}

func (handler Driver) signSourceURL(ctx context.Context, path string, ttl int64, fileName string) (string, error) {
	fmt.Println("signSourceURL")
	input := &obs.CreateSignedUrlInput{}
	input.Expires = *(*int)(unsafe.Pointer(&ttl))
	input.Method = obs.HttpMethodGet
	input.Bucket = handler.bucket
	input.Key = path
	signedUrl, err := handler.client.CreateSignedUrl(input)
	if err != nil {
		return "", err
	}

	//signedURL, err := handler.bucket.SignURL(path, oss.HTTPGet, ttl, options...)
	//if err != nil {
	//	return "", err
	//}

	// 将最终生成的签名URL域名换成用户自定义的加速域名（如果有）
	finalURL, err := url.Parse(signedUrl.SignedUrl)
	if err != nil {
		return "", err
	}

	// 优先使用https
	finalURL.Scheme = "https"

	// 公有空间替换掉Key及不支持的头
	if !handler.Policy.IsPrivate {
		query := finalURL.Query()
		query.Del("AWSAccessKeyId")
		query.Del("Signature")
		query.Del("response-content-disposition")
		query.Del("x-oss-traffic-limit")
		finalURL.RawQuery = query.Encode()
	}

	if handler.Policy.BaseURL != "" {
		cdnURL, err := url.Parse(handler.Policy.BaseURL)
		if err != nil {
			return "", err
		}
		finalURL.Host = cdnURL.Host
		finalURL.Scheme = cdnURL.Scheme
	}

	return finalURL.String(), nil
}

// Token 获取上传策略和认证Token
func (handler Driver) Token(ctx context.Context, TTL int64, key string) (serializer.UploadCredential, error) {
	fmt.Println("Token 获取上传策略和认证Token")
	fmt.Println(ctx)
	fmt.Println(TTL)
	fmt.Println(key)
	// 读取上下文中生成的存储路径
	savePath, ok := ctx.Value(fsctx.SavePathCtx).(string)
	if !ok {
		return serializer.UploadCredential{}, errors.New("无法获取存储路径")
	}

	// 生成回调地址
	fmt.Println("生成回调地址")
	siteURL := model.GetSiteURL()
	apiBaseURI, _ := url.Parse("/api/v3/callback/obs/" + key)
	apiURL := siteURL.ResolveReference(apiBaseURI)

	// 回调策略
	callbackPolicy := CallbackPolicy{
		CallbackURL:      apiURL.String(),
		CallbackBody:     `{"name":${x:fname},"source_name":${object},"size":${size},"pic_info":"${imageInfo.width},${imageInfo.height}"}`,
		CallbackBodyType: "application/json",
	}

	// 上传策略
	fmt.Println("生成上传策略")
	postPolicy := UploadPolicy{
		Expiration: time.Now().UTC().Add(time.Duration(TTL) * time.Second).Format(time.RFC3339),
		Conditions: []interface{}{
			map[string]string{"bucket": "test-abc"},
			[]string{"starts-with", "$key", path.Dir(savePath)},
		},
	}

	if handler.Policy.MaxSize > 0 {
		postPolicy.Conditions = append(postPolicy.Conditions,
			[]interface{}{"content-length-range", 0, handler.Policy.MaxSize})
	}

	return handler.getUploadCredential(ctx, postPolicy, callbackPolicy, TTL)
}

func (handler Driver) getUploadCredential(ctx context.Context, policy UploadPolicy, callback CallbackPolicy, TTL int64) (serializer.UploadCredential, error) {
	// 读取上下文中生成的存储路径
	savePath, ok := ctx.Value(fsctx.SavePathCtx).(string)
	if !ok {
		return serializer.UploadCredential{}, errors.New("无法获取存储路径")
	}
	fmt.Println("存储路径：",savePath)

	// 处理回调策略
	callbackPolicyEncoded := ""
	if callback.CallbackURL != "" {
		callbackPolicyJSON, err := json.Marshal(callback)
		if err != nil {
			return serializer.UploadCredential{}, err
		}
		callbackPolicyEncoded = base64.StdEncoding.EncodeToString(callbackPolicyJSON)
		policy.Conditions = append(policy.Conditions, map[string]string{"callback": callbackPolicyEncoded})
	}

	// 编码上传策略
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return serializer.UploadCredential{}, err
	}
	policyEncoded := base64.StdEncoding.EncodeToString(policyJSON)

	// 签名上传策略
	hmacSign := hmac.New(sha1.New, []byte("mcMllKTwG5ubrfRASvjZtKoEkgK4ucMMnRBRqupL"))
	_, err = io.WriteString(hmacSign, policyEncoded)
	if err != nil {
		return serializer.UploadCredential{}, err
	}
	signature := base64.StdEncoding.EncodeToString(hmacSign.Sum(nil))

	return serializer.UploadCredential{
		Policy:    fmt.Sprintf("%s:%s", callbackPolicyEncoded, policyEncoded),
		Path:      savePath,
		AccessKey: "PAIOWFSCLFH2MA4ZD4LM",
		Token:     signature,
	}, nil
}
