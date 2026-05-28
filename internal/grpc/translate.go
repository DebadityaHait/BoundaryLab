// SPDX-License-Identifier: MIT
package grpc

import (
	"encoding/json"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"boundarylab.local/boundarylab/pkg/boundarylab"
)

func translateRequest(envoyReq *authv3.CheckRequest) boundarylab.CheckRequest {
	attrs := envoyReq.GetAttributes()
	http := attrs.GetRequest().GetHttp()

	toolName := http.GetMethod() + " " + http.GetPath()
	if toolName == " " {
		toolName = "unknown"
	}

	headers := http.GetHeaders()
	sessionID := headers["x-boundarylab-session"]
	if sessionID == "" {
		sessionID = headers["x-request-id"]
	}
	if sessionID == "" {
		sessionID = "grpc-ext-authz"
	}

	argsJSON, _ := json.Marshal(map[string]any{
		"method":  http.GetMethod(),
		"path":    http.GetPath(),
		"headers": headers,
	})

	return boundarylab.CheckRequest{
		Tool:      toolName,
		Args:      argsJSON,
		SessionID: sessionID,
	}
}

func translateResponse(resp boundarylab.CheckResponse) *authv3.CheckResponse {
	switch resp.Decision.Action {
	case boundarylab.ActionAllow:
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{
				OkResponse: &authv3.OkHttpResponse{},
			},
		}
	case boundarylab.ActionAudit:
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{
				OkResponse: &authv3.OkHttpResponse{
					Headers: []*corev3.HeaderValueOption{
						{Header: &corev3.HeaderValue{Key: "x-boundarylab-audited", Value: "true"}},
					},
				},
			},
		}
	case boundarylab.ActionRequireApproval:
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
					Headers: []*corev3.HeaderValueOption{
						{Header: &corev3.HeaderValue{Key: "x-boundarylab-approval-required", Value: "true"}},
					},
				},
			},
		}
	case boundarylab.ActionDeny:
		return denyResponse(resp.Decision.Reason)
	default:
		return denyResponse(resp.Decision.Reason)
	}
}

func denyResponse(reason string) *authv3.CheckResponse {
	if len(reason) > 256 {
		reason = reason[:256] + "..."
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   reason,
			},
		},
	}
}
