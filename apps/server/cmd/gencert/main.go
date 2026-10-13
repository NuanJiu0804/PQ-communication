// gencert 生成本地开发用的自签名 TLS 证书(纯标准库,无需 OpenSSL)。
//
// 用法:
//
//	go run ./cmd/gencert                 # 写入 certs/dev-cert.pem 与 certs/dev-key.pem
//	go run ./cmd/gencert -host localhost,127.0.0.1,::1,myhost -out certs
//
// 证书覆盖 localhost / 127.0.0.1 / ::1(可用 -host 追加),有效期一年。
// 说明:后量子加固在 TLS「密钥交换」(X25519MLKEM768),与证书签名算法无关;
// 这里用 Ed25519 签名的自签证书即可。生产环境请换用受信任 CA 签发的证书。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "生成证书失败: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	hosts := flag.String("host", "localhost,127.0.0.1,::1", "证书覆盖的主机名/IP(逗号分隔)")
	outDir := flag.String("out", "certs", "证书输出目录")
	flag.Parse()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("生成 Ed25519 密钥: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("生成证书序列号: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Post-Quantum Hybrid E2EE IM Dev"}, CommonName: "Post-Quantum Hybrid E2EE IM Development CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range strings.Split(*hosts, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return fmt.Errorf("签发证书: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("编码私钥: %w", err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("创建输出目录: %w", err)
	}
	certPath := filepath.Join(*outDir, "dev-cert.pem")
	keyPath := filepath.Join(*outDir, "dev-key.pem")

	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	// 私钥权限收紧到 0600。
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}

	fmt.Printf("已生成自签证书:\n  证书: %s\n  私钥: %s\n覆盖主机: %s\n有效期: 一年\n",
		certPath, keyPath, *hosts)
	fmt.Println("在 .env 设置 TLS_ENABLED=true 后,后端将以 HTTPS(TLS 1.3 + 混合后量子)启动。")
	return nil
}

func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("打开 %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("写入 %s: %w", path, err)
	}
	return nil
}
