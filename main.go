package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
)

var (
	vaultAddr     string
	checkInterval string
	s3BucketName  string
	httpClient    http.Client

	sess session.Session

	kmsClient kms.KMS
	kmsKeyID  string

	s3Client s3.S3
)

func main() {
	log.Println("Starting the Watchman service...")

	vaultAddr = os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://127.0.0.1:8200"
	}

	checkInterval = os.Getenv("CHECK_INTERVAL")
	if checkInterval == "" {
		checkInterval = "30"
	}

	i, err := strconv.Atoi(checkInterval)
	if err != nil {
		log.Fatalf("CHECK_INTERVAL is invalid: %s", err)
	}

	checkIntervalDuration := time.Duration(i) * time.Second

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(endpoints.UsEast1RegionID),
	})
	if err != nil {
		log.Fatalf("Error creating AWS session: %s", err)
	}

	s3BucketName = os.Getenv("S3_BUCKET_NAME")
	if s3BucketName == "" {
		log.Fatal("S3_BUCKET_NAME environmnt variable must be set")
	}

	kmsKeyID = os.Getenv("KMS_KEY_ID")
	if kmsKeyID == "" {
		log.Fatal("KMS_KEY_ID environment variable must be set")
	}

	s3Client = *s3.New(sess)
	kmsClient = *kms.New(sess)

	httpClient = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	signalCh := make(chan os.Signal)
	signal.Notify(signalCh,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGKILL,
	)

	stop := func() {
		log.Printf("Shutting Down")
		os.Exit(0)
	}

	for {
		select {
		case <-signalCh:
			stop()
		default:
		}
		response, err := httpClient.Head(vaultAddr + "/v1/sys/health")

		if response != nil && response.Body != nil {
			response.Body.Close()
		}

		if err != nil {
			log.Println(err)
			time.Sleep(checkIntervalDuration)
			continue
		}

		switch response.StatusCode {
		case 200:
			log.Println("Vault is initialized and unsealed.")
		case 429:
			log.Println("Vault is unsealed and in standby mode.")
		case 501:
			log.Println("Vault is not initialized. Initializing and unsealing...")
			initialize()
			unseal()
		case 503:
			log.Println("Vault is sealed. Unsealing...")
			unseal()
		default:
			log.Printf("Vault is in an unknown state. Status code: %d", response.StatusCode)
		}

		log.Printf("Next check is in %s", checkIntervalDuration)

		select {
		case <-signalCh:
			stop()
		case <-time.After(checkIntervalDuration):
		}
	}
}

func initialize() {
	initRequest := InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}

	initRequestData, err := json.Marshal(&initRequest)
	if err != nil {
		log.Println(err)
		return
	}

	r := bytes.NewReader(initRequestData)
	request, err := http.NewRequest("PUT", vaultAddr+"/v1/sys/init", r)
	if err != nil {
		log.Println(err)
		return
	}

	response, err := httpClient.Do(request)
	if err != nil {
		log.Println(err)
		return
	}
	defer response.Body.Close()

	initRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return
	}

	if response.StatusCode != 200 {
		log.Printf("init: non 200 status code: %d", response.StatusCode)
		return
	}

	var initResponse InitResponse

	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		log.Println(err)
		return
	}

	log.Println("Encrypting unseal keys and the root token...")

	rootTokenEncryptRequest := &kms.EncryptInput{
		KeyId:     aws.String(kmsKeyID),
		Plaintext: []byte(initResponse.RootToken),
	}

	rootTokenEncryptResponse, err := kmsClient.Encrypt(rootTokenEncryptRequest)
	if err != nil {
		log.Println(err)
		return
	}

	unsealKeysEncryptRequest := &kms.EncryptInput{
		KeyId:     aws.String(kmsKeyID),
		Plaintext: []byte(initRequestResponseBody),
	}

	unsealKeysEncryptResponse, err := kmsClient.Encrypt(unsealKeysEncryptRequest)
	if err != nil {
		log.Println(err)
		return
	}

	unsealKeysStorageRequest := &s3.PutObjectInput{
		Bucket: aws.String(s3BucketName),
		Key:    aws.String("unseal-keys.json.enc"),
		Body:   bytes.NewReader(unsealKeysEncryptResponse.CiphertextBlob),
	}

	_, err = s3Client.PutObject(unsealKeysStorageRequest)
	if err != nil {
		log.Println(err)
	}

	log.Printf("Unseal keys written to s3://%s/%s", s3BucketName, "unseal-keys.json.enc")

	rootTokenStorageRequest := &s3.PutObjectInput{
		Bucket: aws.String(s3BucketName),
		Key:    aws.String("root-token.enc"),
		Body:   bytes.NewReader(rootTokenEncryptResponse.CiphertextBlob),
	}

	_, err = s3Client.PutObject(rootTokenStorageRequest)
	if err != nil {
		log.Println(err)
	}

	log.Printf("Root token written to s3://%s/%s", s3BucketName, "root-token.enc")

	log.Println("Initialization complete.")
}

func unseal() {
	unsealKeysObject, err := s3Client.GetObject(
		&s3.GetObjectInput{
			Bucket: aws.String(s3BucketName),
			Key:    aws.String("unseal-keys.json.enc"),
		},
	)
	if err != nil {
		log.Println(err)
		return
	}

	unsealKeysData, err := ioutil.ReadAll(unsealKeysObject.Body)
	if err != nil {
		log.Println(err)
		return
	}

	unsealKeysDecryptResponse, err := kmsClient.Decrypt(
		&kms.DecryptInput{
			CiphertextBlob: unsealKeysData,
		},
	)
	if err != nil {
		log.Println(err)
		return
	}

	var initResponse InitResponse

	if err := json.Unmarshal(unsealKeysDecryptResponse.Plaintext, &initResponse); err != nil {
		log.Println(err)
		return
	}

	for _, key := range initResponse.KeysBase64 {
		done, err := unsealOne(key)
		if done {
			return
		}

		if err != nil {
			log.Println(err)
			return
		}
	}
}

func unsealOne(key string) (bool, error) {
	unsealRequest := UnsealRequest{
		Key: key,
	}

	unsealRequestData, err := json.Marshal(&unsealRequest)
	if err != nil {
		return false, err
	}

	r := bytes.NewReader(unsealRequestData)
	request, err := http.NewRequest(http.MethodPut, vaultAddr+"/v1/sys/unseal", r)
	if err != nil {
		return false, err
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return false, fmt.Errorf("unseal: non-200 status code: %d", response.StatusCode)
	}

	unsealRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	var unsealResponse UnsealResponse
	if err := json.Unmarshal(unsealRequestResponseBody, &unsealResponse); err != nil {
		return false, err
	}

	if !unsealResponse.Sealed {
		return true, nil
	}

	return false, nil
}

type InitRequest struct {
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
}

type InitResponse struct {
	Keys       []string `json:"keys"`
	KeysBase64 []string `json:"keys_base64"`
	RootToken  string   `json:"root_token"`
}

type UnsealRequest struct {
	Key   string `json:"key"`
	Reset bool   `json:"reset"`
}

type UnsealResponse struct {
	Sealed   bool `json:"sealed"`
	T        int  `json:"t"`
	N        int  `json:"n"`
	Progress int  `json:"progress"`
}
