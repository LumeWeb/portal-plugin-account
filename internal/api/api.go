package api

import (
	_ "embed"
	"errors"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/messages"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	"go.lumeweb.com/portal/config"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/event"
	"go.lumeweb.com/portal/middleware"
	"go.lumeweb.com/portal/middleware/swagger"
	portal_dashboard "go.lumeweb.com/web/go/portal-dashboard"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"strings"
)

//go:embed swagger.yaml
var swagSpec []byte

var _ core.API = (*API)(nil)

type API struct {
	ctx      core.Context
	config   config.Manager
	user     core.UserService
	auth     core.AuthService
	password core.PasswordResetService
	otp      core.OTPService
	logger   *core.Logger
}

func (a *API) Config() config.APIConfig {
	return &pluginConfig.APIConfig{}
}

func (a *API) Name() string {
	return "account"
}

func NewAPI() (*API, []core.ContextBuilderOption, error) {
	api := &API{}

	opts := core.ContextOptions(
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			api.ctx = ctx
			api.config = ctx.Config()
			api.user = ctx.Service(core.USER_SERVICE).(core.UserService)
			api.auth = ctx.Service(core.AUTH_SERVICE).(core.AuthService)
			api.password = ctx.Service(core.PASSWORD_RESET_SERVICE).(core.PasswordResetService)
			api.otp = ctx.Service(core.OTP_SERVICE).(core.OTPService)
			api.logger = ctx.APILogger(api)

			return nil
		}),
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			err := event.FireUseServicerSubdomainSetEvent(ctx, api.Subdomain())
			if err != nil {
				return err
			}
			return nil
		}),
	)

	return api, opts, nil
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request messages.LoginRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	exists, _, err := a.user.EmailExists(request.Email)
	if err != nil {
		a.logger.Error("failed to check if email exists", zap.Error(err))
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	if !exists {
		err := core.NewAccountError(core.ErrKeyInvalidLogin, nil)
		_ = ctx.Error(err, http.StatusUnauthorized)
		return
	}

	jwt, user, err := a.auth.LoginPassword(request.Email, request.Password, r.RemoteAddr, request.Remember)
	if err != nil || user == nil {
		err := core.NewAccountError(core.ErrKeyInvalidLogin, err)
		_ = ctx.Error(err, http.StatusUnauthorized)
		if err != nil {
			a.logger.Error("failed to login", zap.Error(err))
		}
		return
	}

	rootDomain := "https://" + a.ctx.Config().Config().Core.Domain
	vals := url.Values{}
	vals.Add(a.AuthTokenName(), jwt)

	redirectURL := rootDomain + "/api/auth/complete?" + vals.Encode()

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (a *API) register(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request messages.RegisterRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	if len(request.FirstName) == 0 || len(request.LastName) == 0 {
		err := core.NewAccountError(core.ErrKeyAccountCreationFailed, nil)
		_ = ctx.Error(err, http.StatusBadRequest)
		return
	}

	user, err := a.user.CreateAccount(request.Email, request.Password, true)
	if err != nil {
		_ = ctx.Error(err, http.StatusUnauthorized)
		a.logger.Error("failed to update account name", zap.Error(err))
		return
	}

	err = a.user.UpdateAccountName(user.ID, request.FirstName, request.LastName)
	if err != nil {
		err := core.NewAccountError(core.ErrKeyAccountCreationFailed, err)
		_ = ctx.Error(err, http.StatusBadRequest)
		a.logger.Error("failed to update account name", zap.Error(err))
		return
	}
}

func (a *API) verifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request messages.VerifyEmailRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	if request.Email == "" || request.Token == "" {
		_ = ctx.Error(errors.New("invalid request"), http.StatusBadRequest)
		return
	}

	err = a.user.VerifyEmail(request.Email, request.Token)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *API) resendVerifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)

	if !ok {
		return
	}

	err := a.user.SendEmailVerification(user)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *API) otpGenerate(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)

	if !ok {
		return
	}

	otp, err := a.otp.OTPGenerate(user)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	response := &messages.OTPGenerateResponse{
		OTP: otp,
	}
	ctx.Encode(response)
}

func (a *API) otpVerify(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)

	if !ok {
		return

	}

	var request messages.OTPVerifyRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	err = a.otp.OTPEnable(user, request.OTP)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
func (a *API) otpValidate(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)

	if !ok {
		return
	}

	var request messages.OTPValidateRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	jwt, err := a.auth.LoginOTP(user, request.OTP)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	core.SetAuthCookie(w, a.ctx, jwt)
	core.SendJWT(w, jwt)

	response := &messages.LoginResponse{
		Token: jwt,
		Otp:   false,
	}
	ctx.Encode(response)
}
func (a *API) otpDisable(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)

	if !ok {
		return
	}

	var request messages.OTPDisableRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	valid, _, err := a.auth.ValidLoginByUserID(user, request.Password)
	if err != nil {
		err := core.NewAccountError(core.ErrKeyDatabaseOperationFailed, err)
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	if !valid {
		err := core.NewAccountError(core.ErrKeyInvalidLogin, nil)
		_ = ctx.Error(err, http.StatusUnauthorized)
		return
	}

	err = a.otp.OTPDisable(user)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
func (a *API) passwordResetRequest(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request messages.PasswordResetRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	exists, user, err := a.user.EmailExists(request.Email)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	if !exists {
		_ = ctx.Error(errors.New("invalid request"), http.StatusBadRequest)
		return
	}

	err = a.password.SendPasswordReset(user)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *API) passwordResetConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request messages.PasswordResetVerifyRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	exists, _, err := a.user.EmailExists(request.Email)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	if !exists {
		_ = ctx.Error(errors.New("invalid request"), http.StatusBadRequest)
		return
	}

	err = a.password.ResetPassword(request.Email, request.Password, request.Token)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
func (a *API) ping(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	token, ok := a.getAuthToken(ctx)

	if !ok {
		return
	}

	core.EchoAuthCookie(w, r, a.ctx)
	core.SendJWT(w, token)

	response := &messages.PongResponse{
		Ping:  "pong",
		Token: token,
	}
	ctx.Encode(response)
}

func (a *API) rootAuthComplete(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	userId, ok := a.getUser(ctx)

	if !ok {
		return
	}
	token, ok := a.getAuthToken(ctx)
	if !ok {
		return
	}

	exists, user, err := a.user.AccountExists(userId)
	if err != nil {
		a.logger.Error("failed to check if email exists", zap.Error(err))
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	if !exists {
		err := core.NewAccountError(core.ErrKeyInvalidLogin, nil)
		_ = ctx.Error(err, http.StatusUnauthorized)
		return
	}

	core.SetAuthCookie(w, a.ctx, token)
	core.SendJWT(w, token)

	response := &messages.LoginResponse{
		Token: token,
		Otp:   user.OTPEnabled && user.OTPVerified,
	}

	ctx.Encode(response)
}

func (a *API) accountInfo(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)

	if !ok {
		return
	}

	_, acct, err := a.user.AccountExists(user)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	response := &messages.AccountInfoResponse{
		ID:        acct.ID,
		Email:     acct.Email,
		FirstName: acct.FirstName,
		LastName:  acct.LastName,
		Verified:  acct.Verified,
	}
	ctx.Encode(response)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	core.ClearAuthCookie(w, a.ctx)
	w.WriteHeader(http.StatusOK)
}

func (a *API) uploadLimit(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	response := &messages.UploadLimitResponse{
		Limit: a.config.Config().Core.PostUploadLimit,
	}
	ctx.Encode(response)
}

func (a *API) updateEmail(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)

	if !ok {
		return
	}

	var request messages.UpdateEmailRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	err = a.user.UpdateAccountEmail(user, request.Email, request.Password)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *API) updatePassword(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)

	if !ok {
		return
	}

	var request messages.UpdatePasswordRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	err = a.user.UpdateAccountPassword(user, request.CurrentPassword, request.NewPassword)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *API) meta(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	response := &messages.MetaResponse{
		Domain: a.config.Config().Core.Domain,
	}
	ctx.Encode(response)
}

func (a *API) getUser(ctx httputil.RequestContext) (uint, bool) {
	user, err := middleware.GetUserFromContext(ctx)

	if err != nil {
		_ = ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
		return 0, false
	}

	return user, true
}

func (a *API) getAuthToken(ctx httputil.RequestContext) (string, bool) {
	token, err := middleware.GetAuthTokenFromContext(ctx)

	if err != nil {
		_ = ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
		return "", false
	}

	return token, true
}

func (a *API) Configure(router *mux.Router) error {
	// CORS configuration
	corsOpts := cors.Options{
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}
	corsHandler := cors.New(corsOpts)

	// Middleware functions
	loginAuthMw2fa := middleware.AuthMiddleware(middleware.AuthMiddlewareOptions{
		Context:        a.ctx,
		Purpose:        core.JWTPurpose2FA,
		EmptyAllowed:   true,
		ExpiredAllowed: true,
	})

	authMw := middleware.AuthMiddleware(middleware.AuthMiddlewareOptions{
		Context: a.ctx,
		Purpose: core.JWTPurposeNone,
	})

	pingAuthMw := middleware.AuthMiddleware(middleware.AuthMiddlewareOptions{
		Context: a.ctx,
		Purpose: core.JWTPurposeLogin,
	})

	// Swagger routes
	err := swagger.Swagger(swagSpec, router)
	if err != nil {
		return err
	}

	router.Use(corsHandler.Handler)

	// Routes
	router.HandleFunc("/api/upload-limit", a.uploadLimit).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/meta", a.meta).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/auth/register", a.register).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/account/password-reset/request", a.passwordResetRequest).Methods("POST")
	router.HandleFunc("/api/account/password-reset/confirm", a.passwordResetConfirm).Methods("POST", "OPTIONS")

	router.HandleFunc("/api/auth/otp/generate", a.otpGenerate).Methods("GET", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/account", a.accountInfo).Methods("GET", "OPTIONS").Use(authMw)

	router.HandleFunc("/api/auth/ping", a.ping).Methods("POST", "OPTIONS").Use(pingAuthMw)
	router.HandleFunc("/api/auth/login", a.login).Methods("POST", "OPTIONS").Use(loginAuthMw2fa, corsHandler.Handler)
	router.HandleFunc("/api/auth/otp/validate", a.otpValidate).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/auth/logout", a.logout).Methods("POST", "OPTIONS").Use(authMw)

	router.HandleFunc("/api/account/verify-email", a.verifyEmail).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/account/verify-email/resend", a.resendVerifyEmail).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/account/otp/verify", a.otpVerify).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/account/otp/disable", a.otpDisable).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/account/update-email", a.updateEmail).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/account/update-password", a.updatePassword).Methods("POST", "OPTIONS").Use(authMw)

	// Catch-all route for client-side app
	router.PathPrefix("/assets/").Handler(portal_dashboard.Handler())
	router.PathPrefix("/").MatcherFunc(
		func(r *http.Request, rm *mux.RouteMatch) bool {
			return !strings.HasPrefix(r.URL.Path, "/api/")
		}).Handler(portal_dashboard.Handler()).Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	})

	rootRouter := core.GetService[core.HTTPService](a.ctx, core.HTTP_SERVICE).Router().Host(a.ctx.Config().Config().Core.Domain).Subrouter()

	rootRouter.Use(pingAuthMw)
	rootRouter.Use(corsHandler.Handler)

	rootRouter.HandleFunc("/api/auth/complete", a.rootAuthComplete).Methods("GET", "OPTIONS")

	return nil
}

func (a *API) Subdomain() string {
	return a.ctx.Config().GetAPI(internal.PLUGIN_NAME).(*pluginConfig.APIConfig).Subdomain
}

func (a *API) AuthTokenName() string {
	return core.AUTH_COOKIE_NAME
}
