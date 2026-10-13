package password

import "testing"

func TestHashAndVerify(t *testing.T) {
	const pw = "correct horse battery staple"
	hash, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash 失败: %v", err)
	}
	if err := Verify(pw, hash); err != nil {
		t.Fatalf("正确口令校验应通过,却失败: %v", err)
	}
	if err := Verify("wrong password", hash); err == nil {
		t.Fatal("错误口令校验应失败,却通过了")
	}
}

func TestHashIsSalted(t *testing.T) {
	h1, _ := Hash("same-password")
	h2, _ := Hash("same-password")
	if h1 == h2 {
		t.Fatal("同一口令两次哈希应因随机盐而不同")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	if err := Verify("x", "not-a-valid-phc-string"); err == nil {
		t.Fatal("非法哈希格式应被拒绝")
	}
}
