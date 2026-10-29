package crypto

import (
	"testing"
)

func TestFIPS204Compliance(t *testing.T) {
	report := RunFIPS204Validation()
	if !report.AllPassed {
		t.Fatalf("FIPS 204 validation gagal: %d dari %d tes gagal", report.FailedTests, report.TotalTests)
	}
	t.Logf("Sukses: %d/%d tes FIPS 204 lulus 100%%", report.PassedTests, report.TotalTests)
}
