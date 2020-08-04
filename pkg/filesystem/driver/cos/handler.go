package cos

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	model "github.com/HFO4/cloudreve/models"
	"github.com/HFO4/cloudreve/obs"
	"github.com/HFO4/cloudreve/pkg/filesystem/fsctx"
	"github.com/HFO4/cloudreve/pkg/filesystem/response"
	"github.com/HFO4/cloudreve/pkg/request"
	"github.com/HFO4/cloudreve/pkg/serializer"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unsafe"
)

// UploadPolicy 腾讯云COS上传策略
type UploadPolicy struct {
	Expiration string        `json:"expiration"`
	Conditions []interface{} `json:"conditions"`
}

// MetaData 文件元信息
type MetaData struct {
	Size        uint64
	CallbackKey string
	CallbackURL string
}

type urlOption struct {
	Speed              int    `url:"x-cos-traffic-limit,omitempty"`
	ContentDescription string `url:"response-content-disposition,omitempty"`
}

// Driver 腾讯云COS适配器模板
//type Driver struct {
//	Policy     *model.Policy
//	Client     *cossdk.Client
//	HTTPClient request.Client
//}

// Driver OBS策略适配器
type Driver struct {
	Policy *model.Policy
	//client     *oss.Client
	//bucket     *oss.Bucket
	client     *obs.ObsClient
	bucket     string //*obs.Bucket
	HTTPClient request.Client
}

// InitOSSClient 初始化OBS鉴权客户端
func (handler *Driver) InitOBSClient() error {
	fmt.Println("InitOBSClient 初始化COS-OBS鉴权客户端")
	if handler.Policy == nil {
		return errors.New("存储策略为空")
	}

	if handler.client == nil {
		// 初始化客户端
		fmt.Println("obsobsobs")
		fmt.Printf("endpoit: %v, ak: %v, sk: %v, bucket: %v\n",
			handler.Policy.Server, handler.Policy.AccessKey, handler.Policy.SecretKey, handler.Policy.BucketName)
		//client, err := oss.New(handler.Policy.Server, handler.Policy.AccessKey, handler.Policy.SecretKey)
		//obsClient, err := obs.New(handler.Policy.AccessKey, handler.Policy.SecretKey, handler.Policy.Server)
		obsClient, err := obs.New(handler.Policy.AccessKey, handler.Policy.SecretKey, handler.Policy.Server, obs.WithPathStyle(true))
		if err != nil {
			return err
		}
		handler.client = obsClient

		// 初始化存储桶
		//bucket, err := client.Bucket(handler.Policy.BucketName)
		//if err != nil {
		//	return err
		//}
		handler.bucket = handler.Policy.BucketName

	}

	return nil
}


// List 列出OSS上的文件
func (handler Driver) List(ctx context.Context, base string, recursive bool) ([]response.Object, error) {
	fmt.Println("List 列出OSS上的文件")
	// 初始化客户端
	if err := handler.InitOBSClient(); err != nil {
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
		input.Bucket = handler.Policy.BucketName
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

// CORS 创建跨域策略
func (handler *Driver) CORS() error {
	// 初始化客户端
	if err := handler.InitOBSClient(); err != nil {
		return err
	}

	input := &obs.SetBucketCorsInput{}
	input.Bucket = handler.Policy.BucketName
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

// Get 获取文件
func (handler Driver) Get(ctx context.Context, path string) (response.RSCloser, error) {
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
	if err := handler.InitOBSClient(); err != nil {
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
	input.Bucket = handler.Policy.BucketName
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
	if err := handler.InitOBSClient(); err != nil {
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
	input.Bucket = handler.Policy.BucketName
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
	//var (
	//	thumbSize = [2]uint{400, 300}
	//	ok        = false
	//)
	//if thumbSize, ok = ctx.Value(fsctx.ThumbSizeCtx).([2]uint); !ok {
	//	return nil, errors.New("无法获取缩略图尺寸设置")
	//}
	//thumbParam := fmt.Sprintf("imageMogr2/thumbnail/%dx%d", thumbSize[0], thumbSize[1])
	//
	//source, err := handler.signSourceURL(
	//	ctx,
	//	path,
	//	int64(model.GetIntSetting("preview_timeout", 60)),
	//	&urlOption{},
	//)
	//if err != nil {
	//	return nil, err
	//}
	//
	//thumbURL, _ := url.Parse(source)
	//thumbQuery := thumbURL.Query()
	//thumbQuery.Add(thumbParam, "")
	//thumbURL.RawQuery = thumbQuery.Encode()
	//
	//return &response.ContentResponse{
	//	Redirect: true,
	//	URL:      thumbURL.String(),
	//}, nil
	fmt.Println("Thumb 获取文件缩略图")
	// 初始化客户端
	if err := handler.InitOBSClient(); err != nil {
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
	if err := handler.InitOBSClient(); err != nil {
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
	input.Bucket = handler.Policy.BucketName
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

	// TODO 下面这几行将url替换为存储同策略的 ”文件资源根URL“
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
	// 读取上下文中生成的存储路径
	savePath, ok := ctx.Value(fsctx.SavePathCtx).(string)
	if !ok {
		return serializer.UploadCredential{}, errors.New("无法获取存储路径")
	}

	// 生成回调地址
	siteURL := model.GetSiteURL()
	apiBaseURI, _ := url.Parse("/api/v3/callback/cos/" + key)
	apiURL := siteURL.ResolveReference(apiBaseURI).String()

	// 上传策略
	startTime := time.Now()
	endTime := startTime.Add(time.Duration(TTL) * time.Second)
	keyTime := fmt.Sprintf("%d;%d", startTime.Unix(), endTime.Unix())
	//postPolicy := UploadPolicy{
	//	Expiration: endTime.UTC().Format(time.RFC3339),
	//	Conditions: []interface{}{
	//		map[string]string{"bucket": handler.Policy.BucketName},
	//		map[string]string{"$key": savePath},
	//		map[string]string{"x-cos-meta-callback": apiURL},
	//		map[string]string{"x-cos-meta-key": key},
	//		map[string]string{"q-sign-algorithm": "sha1"},
	//		map[string]string{"q-ak": handler.Policy.AccessKey},
	//		map[string]string{"q-sign-time": keyTime},
	//	},
	//}
	postPolicy := UploadPolicy{
		Expiration: time.Now().UTC().Add(time.Duration(TTL) * time.Second).Format(time.RFC3339),
		Conditions: []interface{}{
			map[string]string{"bucket": handler.Policy.BucketName},
			[]string{"starts-with", "$key", path.Dir(savePath)},
		},
	}

	if handler.Policy.MaxSize > 0 {
		postPolicy.Conditions = append(postPolicy.Conditions,
			[]interface{}{"content-length-range", 0, handler.Policy.MaxSize})
	}

	res, err := handler.getUploadCredential(ctx, postPolicy, keyTime)
	if err == nil {
		res.Callback = apiURL
		res.Key = key
	}

	return res, err

}

//// Meta 获取文件信息
//func (handler Driver) Meta(ctx context.Context, path string) (*MetaData, error) {
//	//todo modify to obs
//	res, err := handler.Client.Object.Head(ctx, path, &cossdk.ObjectHeadOptions{})
//	if err != nil {
//		return nil, err
//	}
//	return &MetaData{
//		Size:        uint64(res.ContentLength),
//		//CallbackKey: res.Header.Get("x-cos-meta-key"),
//		//CallbackURL: res.Header.Get("x-cos-meta-callback"),
//	}, nil
//}

func (handler Driver) getUploadCredential(ctx context.Context, policy UploadPolicy, keyTime string) (serializer.UploadCredential, error) {
/*	// 读取上下文中生成的存储路径
	savePath, ok := ctx.Value(fsctx.SavePathCtx).(string)
	if !ok {
		return serializer.UploadCredential{}, errors.New("无法获取存储路径")
	}

	// 编码上传策略
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return serializer.UploadCredential{}, err
	}
	policyEncoded := base64.StdEncoding.EncodeToString(policyJSON)

	// 签名上传策略
	hmacSign := hmac.New(sha1.New, []byte(handler.Policy.SecretKey))
	_, err = io.WriteString(hmacSign, keyTime)
	if err != nil {
		return serializer.UploadCredential{}, err
	}
	signKey := fmt.Sprintf("%x", hmacSign.Sum(nil))

	sha1Sign := sha1.New()
	_, err = sha1Sign.Write(policyJSON)
	if err != nil {
		return serializer.UploadCredential{}, err
	}
	stringToSign := fmt.Sprintf("%x", sha1Sign.Sum(nil))

	// 最终签名
	hmacFinalSign := hmac.New(sha1.New, []byte(signKey))
	_, err = hmacFinalSign.Write([]byte(stringToSign))
	if err != nil {
		return serializer.UploadCredential{}, err
	}
	signature := hmacFinalSign.Sum(nil)

	return serializer.UploadCredential{
		Policy:    policyEncoded,
		Path:      savePath,
		AccessKey: handler.Policy.AccessKey,
		Token:     fmt.Sprintf("%x", signature),
		KeyTime:   keyTime,
	}, nil*/
	// 读取上下文中生成的存储路径
	savePath, ok := ctx.Value(fsctx.SavePathCtx).(string)
	if !ok {
		return serializer.UploadCredential{}, errors.New("无法获取存储路径")
	}
	fmt.Println("存储路径：",savePath)

	// 处理回调策略
	//callbackPolicyEncoded := ""
	//if callback.CallbackURL != "" {
	//	callbackPolicyJSON, err := json.Marshal(callback)
	//	if err != nil {
	//		return serializer.UploadCredential{}, err
	//	}
	//	callbackPolicyEncoded = base64.StdEncoding.EncodeToString(callbackPolicyJSON)
	//	policy.Conditions = append(policy.Conditions, map[string]string{"callback": callbackPolicyEncoded})
	//}

	// 编码上传策略
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return serializer.UploadCredential{}, err
	}
	policyEncoded := base64.StdEncoding.EncodeToString(policyJSON)

	// 签名上传策略
	hmacSign := hmac.New(sha1.New, []byte(handler.Policy.SecretKey))
	_, err = io.WriteString(hmacSign, policyEncoded)
	if err != nil {
		return serializer.UploadCredential{}, err
	}
	signature := base64.StdEncoding.EncodeToString(hmacSign.Sum(nil))

	return serializer.UploadCredential{
		Policy:    policyEncoded,
		Path:      savePath,
		AccessKey: handler.Policy.AccessKey,
		Token:     signature,
		KeyTime:   keyTime,
	}, nil
}
