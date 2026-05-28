// SPDX-License-Identifier: MIT
package daemon

import (
	"time"

	"boundarylab.local/boundarylab/internal/audit"
	"boundarylab.local/boundarylab/pkg/boundarylab"
)

func buildAuditRecord(req boundarylab.CheckRequest, resp boundarylab.CheckResponse) audit.AuditRecord {
	return audit.AuditRecord{
		Timestamp:      time.Now().UnixNano(),
		SessionID:      req.SessionID,
		Tool:           req.Tool,
		Args:           req.Args,
		Decision:       resp.Decision,
		LatencyNs:      resp.LatencyNs,
		PolicyID:       resp.Decision.PolicyID,
		EnforcingLayer: resp.EnforcingLayer,
	}
}
