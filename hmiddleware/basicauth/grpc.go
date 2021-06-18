package basicauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
)

// scheme is the Authorization prefix in the header, e.g. `Basic <base 64 blob>`.
const scheme = "basic"

// GRPCAuthFunc creates grpc_auth.AuthFunc. It does authentication using the
// basic auth scheme, and validates any user/password sent using checker.
func GRPCAuthFunc(checker *Checker) func(ctx context.Context) (context.Context, error) {
	return func(ctx context.Context) (context.Context, error) {
		blob, err := grpc_auth.AuthFromMD(ctx, scheme)
		if err != nil {
			return nil, err
		}

		user, pass, ok := parseBasicAuth(blob)
		if !ok {
			//TODO: SA1019: grpc.Errorf is deprecated: use status.Errorf instead.  (staticcheck)
			return nil, grpc.Errorf(codes.Unauthenticated, "unauthenticated") //nolint:staticcheck
		}

		if !checker.Valid(user, pass) {
			//TODO: SA1019: grpc.Errorf is deprecated: use status.Errorf instead.  (staticcheck)
			return nil, grpc.Errorf(codes.PermissionDenied, "permission denied") //nolint:staticcheck
		}

		if checker.roleValidator != nil {
			// According to grpc docs, this method will be in the form:
			// "/service/method".
			method, ok := grpc.Method(ctx)
			if !ok {
				return nil, grpc.Errorf(codes.PermissionDenied, "permission denied. no grpc method found on context") //nolint:staticcheck
			}

			if !checker.roleValidator.Validate(user, method) {
				return nil, grpc.Errorf( //nolint:staticcheck
					codes.PermissionDenied,
					fmt.Sprintf("permission denied. user \"%s\" does not have access to \"%s\"", user, method),
				)
			}
		}

		return ctx, nil
	}
}

var _ credentials.PerRPCCredentials = &GRPCCredentials{}

// GRPCCredentials implements PerRPCCredentials.
type GRPCCredentials struct {
	Username, Password string

	TransportSecurity bool
}

// GetRequestMetadata maps the given credentials to the appropriate request
// headers.
func (c GRPCCredentials) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": basicAuth(c.Username, c.Password),
	}, nil
}

// RequireTransportSecurity implements PerRPCCredentials.
func (c GRPCCredentials) RequireTransportSecurity() bool {
	return c.TransportSecurity
}

func parseBasicAuth(auth string) (user, pass string, ok bool) {
	c, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return
	}

	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}

	user, pass, ok = cs[:s], cs[s+1:], true
	return
}

func basicAuth(user, pass string) string {
	return scheme + " " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}
