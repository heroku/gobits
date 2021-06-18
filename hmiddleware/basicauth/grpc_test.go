package basicauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/examples/route_guide/routeguide"

	"github.com/heroku/x/grpc/grpcclient"
	"github.com/heroku/x/grpc/grpcserver"
	"github.com/heroku/x/testing/testlog"
)

func TestGRPCPerRPCCredentialBasicAuth(t *testing.T) {
	t.Run("valid creds", func(t *testing.T) {
		l, _ := testlog.New()
		mux := http.NewServeMux()

		checker := NewChecker([]Credential{{"user", "pass"}})

		gSrv, hSrv := grpcserver.NewStandardH2C(
			mux,
			grpcserver.AuthInterceptors(
				grpc_auth.UnaryServerInterceptor(GRPCAuthFunc(checker)),
				grpc_auth.StreamServerInterceptor(GRPCAuthFunc(checker)),
			),
			grpcserver.LogEntry(l.WithField("at", "grpc")),
		)

		routeguide.RegisterRouteGuideServer(gSrv, &fakeServer{})

		srv := httptest.NewServer(hSrv.Handler)
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		conn, err := grpcclient.DialH2CContext(
			ctx,
			srv.URL,
			grpc.WithBlock(),
			grpc.WithPerRPCCredentials(&GRPCCredentials{Username: "user", Password: "pass"}),
		)
		if err != nil {
			t.Fatal(err)
		}

		client := routeguide.NewRouteGuideClient(conn)
		_, err = client.GetFeature(context.Background(), &routeguide.Point{})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("invalid username and password", func(t *testing.T) {
		l, _ := testlog.New()
		mux := http.NewServeMux()

		checker := NewChecker([]Credential{{"user", "nope"}})

		gSrv, hSrv := grpcserver.NewStandardH2C(
			mux,
			grpcserver.AuthInterceptors(
				grpc_auth.UnaryServerInterceptor(GRPCAuthFunc(checker)),
				grpc_auth.StreamServerInterceptor(GRPCAuthFunc(checker)),
			),
			grpcserver.LogEntry(l.WithField("at", "grpc")),
		)

		routeguide.RegisterRouteGuideServer(gSrv, &fakeServer{})

		srv := httptest.NewServer(hSrv.Handler)
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		conn, err := grpcclient.DialH2CContext(
			ctx,
			srv.URL,
			grpc.WithBlock(),
			grpc.WithPerRPCCredentials(&GRPCCredentials{Username: "user", Password: "pass"}),
		)
		if err != nil {
			t.Fatal(err)
		}

		client := routeguide.NewRouteGuideClient(conn)
		_, err = client.GetFeature(context.Background(), &routeguide.Point{})
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("valid creds with role validator", func(t *testing.T) {
		l, _ := testlog.New()
		mux := http.NewServeMux()

		checker := NewChecker([]Credential{{"user", "pass"}})
		checker.WithRoleValidator(&fakeRoleValidator{valid: true})

		gSrv, hSrv := grpcserver.NewStandardH2C(
			mux,
			grpcserver.AuthInterceptors(
				grpc_auth.UnaryServerInterceptor(GRPCAuthFunc(checker)),
				grpc_auth.StreamServerInterceptor(GRPCAuthFunc(checker)),
			),
			grpcserver.LogEntry(l.WithField("at", "grpc")),
		)

		routeguide.RegisterRouteGuideServer(gSrv, &fakeServer{})

		srv := httptest.NewServer(hSrv.Handler)
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		conn, err := grpcclient.DialH2CContext(
			ctx,
			srv.URL,
			grpc.WithBlock(),
			grpc.WithPerRPCCredentials(&GRPCCredentials{Username: "user", Password: "pass"}),
		)
		if err != nil {
			t.Fatal(err)
		}

		client := routeguide.NewRouteGuideClient(conn)
		_, err = client.GetFeature(context.Background(), &routeguide.Point{})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("invalid role", func(t *testing.T) {
		l, _ := testlog.New()
		mux := http.NewServeMux()

		checker := NewChecker([]Credential{{"user", "pass"}})
		checker.WithRoleValidator(&fakeRoleValidator{valid: false})

		gSrv, hSrv := grpcserver.NewStandardH2C(
			mux,
			grpcserver.AuthInterceptors(
				grpc_auth.UnaryServerInterceptor(GRPCAuthFunc(checker)),
				grpc_auth.StreamServerInterceptor(GRPCAuthFunc(checker)),
			),
			grpcserver.LogEntry(l.WithField("at", "grpc")),
		)

		routeguide.RegisterRouteGuideServer(gSrv, &fakeServer{})

		srv := httptest.NewServer(hSrv.Handler)
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		conn, err := grpcclient.DialH2CContext(
			ctx,
			srv.URL,
			grpc.WithBlock(),
			grpc.WithPerRPCCredentials(&GRPCCredentials{Username: "user", Password: "pass"}),
		)
		if err != nil {
			t.Fatal(err)
		}

		client := routeguide.NewRouteGuideClient(conn)
		_, err = client.GetFeature(context.Background(), &routeguide.Point{})
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}

type fakeRoleValidator struct {
	valid bool
}

func (frv *fakeRoleValidator) Validate(_, _ string) bool {
	return frv.valid
}

type fakeServer struct {
}

func (s *fakeServer) GetFeature(context.Context, *routeguide.Point) (*routeguide.Feature, error) {
	return &routeguide.Feature{}, nil
}

func (s *fakeServer) ListFeatures(*routeguide.Rectangle, routeguide.RouteGuide_ListFeaturesServer) error {
	return errors.New("unimplemented")
}

func (s *fakeServer) RecordRoute(routeguide.RouteGuide_RecordRouteServer) error {
	return errors.New("unimplemented")
}

func (s *fakeServer) RouteChat(routeguide.RouteGuide_RouteChatServer) error {
	return errors.New("unimplemented")
}
