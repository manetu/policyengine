//
//  Copyright © Manetu Inc. All rights reserved.
//

package envoy

import (
	"context"
	_ "embed" // embed is imported for potential future use with embedded resources
	"encoding/json"
	"fmt"
	"net"
	"sync"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/manetu/policyengine/internal/logging"
	"github.com/manetu/policyengine/pkg/core/auxdata"
	"github.com/manetu/policyengine/pkg/core/backend"
	"github.com/manetu/policyengine/pkg/decisionpoint"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/manetu/policyengine/pkg/core"
)

var logger = logging.GetLogger("policyengine.decisionpoint")

const agent string = "envoy"

const (
	resultHeader   = "x-ext-authz-check-result"
	receivedHeader = "x-ext-authz-check-received"
	resultAllowed  = "allowed"
	resultDenied   = "denied"
)

func returnIfNotTooLong(body string) string {
	// Maximum size of a header accepted by Envoy is 60KiB, so when the request body is bigger than 60KB,
	// we don't return it in a response header to avoid rejecting it by Envoy and returning 431 to the client
	if len(body) > 60000 {
		return "<too-long>"
	}
	return body
}

// ExtAuthzServer implements the ext_authz v2/v3 gRPC and HTTP check request API.
type ExtAuthzServer struct {
	grpcServer *grpc.Server
	pe         core.PolicyEngine
	be         backend.Service
	domain     string
	auxdata    map[string]interface{}

	// For test only
	grpcPort chan int
}

func logRequest(allow string, request *authv3.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	logger.Tracef(agent, "logRequest", "[gRPCv3][%s]: %s%s, attributes: %v", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
}

func (s *ExtAuthzServer) allow(request *authv3.CheckRequest) *authv3.CheckResponse {
	logRequest("allowed", request)
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   resultHeader,
							Value: resultAllowed,
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   receivedHeader,
							Value: returnIfNotTooLong(request.GetAttributes().String()),
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.OK)},
	}
}

func (s *ExtAuthzServer) deny(request *authv3.CheckRequest) *authv3.CheckResponse {
	logRequest("denied", request)
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   "permission denied",
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   resultHeader,
							Value: resultDenied,
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   receivedHeader,
							Value: returnIfNotTooLong(request.GetAttributes().String()),
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
	}
}

// Check implements gRPC v3 check request.
func (s *ExtAuthzServer) Check(ctx context.Context, request *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	attrs := request.GetAttributes()

	jattrs, err := json.Marshal(attrs)
	if err != nil {
		return nil, err
	}

	mattrs := make(map[string]interface{})
	err = json.Unmarshal(jattrs, &mattrs)
	if err != nil {
		return nil, err
	}

	auxdata.MergeAuxData(mattrs, s.auxdata)

	mapper, perr := s.be.GetMapper(ctx, s.domain)
	if perr != nil {
		return nil, perr
	}

	result, perr := mapper.Evaluate(ctx, mattrs)
	if perr != nil {
		logger.Fatalf(agent, "mapper.evaluate", "error evaluating policy: %v", perr)
		return nil, perr
	}

	porc, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	allow, _ := s.pe.Authorize(ctx, string(porc))
	if allow {
		return s.allow(request), nil
	}

	return s.deny(request), nil
}

func (s *ExtAuthzServer) startGRPC(address string, wg *sync.WaitGroup) {
	logger.Infof(agent, "start", "Starting Envoy External Authorization gRPC server on %s", address)
	defer func() {
		wg.Done()
		logger.SysInfof("Stopped gRPC server")
	}()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		logger.Fatalf(agent, "net.listen", "Failed to start gRPC server: %v", err)
		return
	}

	s.grpcServer = grpc.NewServer()
	authv3.RegisterAuthorizationServer(s.grpcServer, s)

	// Store the port for test only. Must be after grpcServer is set to avoid race condition.
	s.grpcPort <- listener.Addr().(*net.TCPAddr).Port

	logger.SysInfof("Starting gRPC server at %s", listener.Addr())
	if err := s.grpcServer.Serve(listener); err != nil {
		logger.Fatalf(agent, "grpc.start", "Failed to serve gRPC server: %v", err)
		return
	}
}

func (s *ExtAuthzServer) run(grpcAddr string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go s.startGRPC(grpcAddr, &wg)
	wg.Wait()
}

// CreateServer creates and starts a new Envoy External Authorization server.
// It returns a Server interface that implements the decisionpoint.Server interface.
// The auxdata parameter, if non-nil, is merged into the mapper input under the "auxdata" key.
func CreateServer(pe core.PolicyEngine, port int, domain string, aux map[string]interface{}) (decisionpoint.Server, error) {
	s := &ExtAuthzServer{
		grpcPort: make(chan int, 1),
		pe:       pe,
		be:       pe.GetBackend(),
		domain:   domain,
		auxdata:  aux,
	}

	go s.run(fmt.Sprintf(":%d", port))

	return s, nil
}

// Stop gracefully stops the ExtAuthzServer by stopping the underlying gRPC server.
func (s *ExtAuthzServer) Stop(ctx context.Context) error {
	s.grpcServer.Stop()
	logger.SysInfof("GRPC server stopped")

	return nil
}
