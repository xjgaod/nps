package tool

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/astaxie/beego/logs"
	"github.com/go-redis/redis"
	"github.com/pkg/errors"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/astaxie/beego"
	"github.com/cnlh/nps/lib/common"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
)

var (
	ports        []int
	ServerStatus []map[string]interface{}
)

func StartSystemInfo() {
	if b, err := beego.AppConfig.Bool("system_info_display"); err == nil && b {
		ServerStatus = make([]map[string]interface{}, 0, 1500)
		go getSeverStatus()
	}
}

func InitAllowPort() {
	p := beego.AppConfig.String("allow_ports")
	ports = common.GetPorts(p)
}

func TestServerPort(p int, m string) (b bool) {
	if p > 65535 || p < 0 {
		return false
	}
	if len(ports) != 0 {
		if !common.InIntArr(ports, p) {
			return false
		}
	}
	if m == "udp" {
		b = common.TestUdpPort(p)
	} else {
		b = common.TestTcpPort(p)
	}
	return
}

func getSeverStatus() {
	for {
		if len(ServerStatus) < 10 {
			time.Sleep(time.Second)
		} else {
			time.Sleep(time.Minute)
		}
		cpuPercet, _ := cpu.Percent(0, true)
		var cpuAll float64
		for _, v := range cpuPercet {
			cpuAll += v
		}
		m := make(map[string]interface{})
		loads, _ := load.Avg()
		m["load1"] = loads.Load1
		m["load5"] = loads.Load5
		m["load15"] = loads.Load15
		m["cpu"] = math.Round(cpuAll / float64(len(cpuPercet)))
		swap, _ := mem.SwapMemory()
		m["swap_mem"] = math.Round(swap.UsedPercent)
		vir, _ := mem.VirtualMemory()
		m["virtual_mem"] = math.Round(vir.UsedPercent)
		conn, _ := net.ProtoCounters(nil)
		io1, _ := net.IOCounters(false)
		time.Sleep(time.Millisecond * 500)
		io2, _ := net.IOCounters(false)
		if len(io2) > 0 && len(io1) > 0 {
			m["io_send"] = (io2[0].BytesSent - io1[0].BytesSent) * 2
			m["io_recv"] = (io2[0].BytesRecv - io1[0].BytesRecv) * 2
		}
		t := time.Now()
		m["time"] = strconv.Itoa(t.Hour()) + ":" + strconv.Itoa(t.Minute()) + ":" + strconv.Itoa(t.Second())

		for _, v := range conn {
			m[v.Protocol] = v.Stats["CurrEstab"]
		}
		if len(ServerStatus) >= 1440 {
			ServerStatus = ServerStatus[1:]
		}
		ServerStatus = append(ServerStatus, m)
	}
}
func GetRdb() (*redis.Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     beego.AppConfig.String("redis_host"),
		Password: beego.AppConfig.String("redis_passwd"), // no password set
		DB:       0,                                      // use default DB
	})
	_, err := rdb.Ping().Result()
	if err != nil {
		return rdb, err
	}
	return rdb, nil
}
func pKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func aesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	origData = pKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func aesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = pKCS5UnPadding(origData)
	return origData, nil
}
func AesDPassGet(password string) (string, error) {
	bytesPass, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		return "", err
	}
	var aeskey = []byte(beego.AppConfig.String("aes_key"))
	tpass, err := aesDecrypt(bytesPass, aeskey)
	if err != nil {
		return "", err
	}
	var pass = string(tpass[:])
	return pass, nil

}
func AesEPassGet(password string) (string, error) {
	var aeskey = []byte(beego.AppConfig.String("aes_key"))
	bytepass := []byte(password)
	xpass, err := aesEncrypt(bytepass, aeskey)
	if err != nil {
		return "", err
	}
	pass64 := base64.StdEncoding.EncodeToString(xpass)
	return pass64, nil

}
func Decrypt(ciphertext string) (string, error) {
	privatekey, err := loadPrivateKeyFile()
	if err != nil {
		return "", fmt.Errorf("get pivate pem failed, error=%s\n",
			err.Error())
	}
	decodedtext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed, error=%s\n",
			err.Error())
	}

	sha256hash := sha256.New()
	decryptedtext, err := rsa.DecryptOAEP(sha256hash, rand.Reader,
		privatekey, decodedtext, nil)
	if err != nil {
		return "", fmt.Errorf("RSA decrypt failed, error=%s\n",
			err.Error())
	}

	return string(decryptedtext), nil
}
func loadPrivateKeyFile() (*rsa.PrivateKey, error) {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	repath := exPath + "/" + beego.AppConfig.String("rsa_private_file")
	keybuffer, err := ioutil.ReadFile(repath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(keybuffer))
	if block == nil {
		return nil, errors.New("private key error!")
	}

	privatekey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse private key error!")
	}

	return privatekey, nil
}
func AuthHeaderAndBody(header string, body []byte) error {
	logs.Info("header is%s", header)
	afterAuth, err := Decrypt(header)
	if err != nil {
		return errors.New("param:Authorization invalid")
	}
	afterAuth = strings.Replace(afterAuth, "\r", "", -1)
	afterAuth = strings.Replace(afterAuth, "\n", "", -1)
	afterAuth = strings.Replace(afterAuth, "\t", "", -1)
	logs.Info("afterAuth is%s", afterAuth)
	var ojson = string(body[:])
	ojson = strings.Replace(ojson, "\r", "", -1)
	ojson = strings.Replace(ojson, "\n", "", -1)
	ojson = strings.Replace(ojson, "\t", "", -1)
	if res := strings.Compare(afterAuth, ojson); res != 0 {
		return errors.New("Auth failed")
	}
	logs.Info("ojson is%s", ojson)
	return nil
}
