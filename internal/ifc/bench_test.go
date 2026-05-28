package ifc

import (
	"testing"

	"boundarylab.local/boundarylab/pkg/boundarylab"
)

var (
	sinkBool  bool
	sinkLabel boundarylab.SecurityLabel
)

func BenchmarkIFC_Dominates(b *testing.B) {
	subject := boundarylab.SecurityLabel{Confidentiality: 100, Integrity: 100, Category: CatCredentials | CatFinance}
	object := boundarylab.SecurityLabel{Confidentiality: 50, Integrity: 50, Category: CatCredentials}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkBool = Dominates(subject, object)
	}
}

func BenchmarkIFC_Join(b *testing.B) {
	a := boundarylab.SecurityLabel{Confidentiality: 100, Integrity: 80, Category: CatCredentials}
	bLabel := boundarylab.SecurityLabel{Confidentiality: 50, Integrity: 100, Category: CatFinance}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkLabel = Join(a, bLabel)
	}
}

func BenchmarkIFC_Meet(b *testing.B) {
	a := boundarylab.SecurityLabel{Confidentiality: 100, Integrity: 80, Category: CatCredentials}
	bLabel := boundarylab.SecurityLabel{Confidentiality: 50, Integrity: 100, Category: CatFinance}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkLabel = Meet(a, bLabel)
	}
}

func BenchmarkIFC_Elevate(b *testing.B) {
	s := &SessionLabels{}
	resource := boundarylab.SecurityLabel{Confidentiality: 50, Integrity: 50, Category: CatCredentials}
	// Pre-create session so getOrCreate doesn't dominate timing.
	s.getOrCreate("bench-sess")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkLabel = s.Elevate("bench-sess", resource)
	}
}
