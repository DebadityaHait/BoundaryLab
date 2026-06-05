package otel_test

import (
	"context"
	"testing"

	boundarylabotel "boundarylab.local/boundarylab/internal/otel"
)

func BenchmarkOTel_DisabledPath(b *testing.B) {
	// Ensure noop providers are active.
	shutdown, err := boundarylabotel.Initialize(boundarylabotel.Config{Enabled: false})
	if err != nil {
		b.Fatalf("Initialize disabled: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		boundarylabotel.RecordEvaluation(ctx, "Bash", "sess1", "allow", "cel", 1000, false)
	}
}
