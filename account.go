package account

import (
	_ "embed"
	"errors"
	"github.com/LumeWeb/httputil"
	"github.com/LumeWeb/portal/config"
	"github.com/LumeWeb/portal/core"
	"github.com/LumeWeb/portal/middleware"
	"github.com/LumeWeb/portal/middleware/swagger"
	"github.com/LumeWeb/web/go/portal-dashboard"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.uber.org/zap"
	"net/http"
)

//go:embed swagger.yaml
var swagSpec []byte

var _ core.API = (*AccountAPI)(nil)

func init() {
	core.RegisterPlugin(factory)
}

type AccountAPI struct {
	ctx         core.Context
	config      config.Manager
	user        core.UserService
	user_verify core.EmailVerificationService
	auth        core.AuthService
	password    core.PasswordResetService
	otp         core.OTPService
	logger      *core.Logger
}

func (a *AccountAPI) Name() string {
	return "account"
}

func NewAccountAPI(ctx core.Context) *AccountAPI {
	return &AccountAPI{
		ctx:         ctx,
		config:      ctx.Config(),
		user:        ctx.Services().User(),
		user_verify: ctx.Services().UserVerify(),
		auth:        ctx.Services().Auth(),
		password:    ctx.Services().Password(),
		otp:         ctx.Services().Otp(),
		logger:      ctx.Logger(),
	}
}

func (a *AccountAPI) login(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request LoginRequest
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

	jwt, user, err := a.auth.LoginPassword(request.Email, request.Password, r.RemoteAddr)
	if err != nil || user == nil {
		err := core.NewAccountError(core.ErrKeyInvalidLogin, err)
		_ = ctx.Error(err, http.StatusUnauthorized)
		if err != nil {
			a.logger.Error("failed to login", zap.Error(err))
		}
		return
	}

	core.SetAuthCookie(w, a.ctx, jwt)
	core.SendJWT(w, jwt)

	response := &LoginResponse{
		Token: jwt,
		Otp:   user.OTPEnabled && user.OTPVerified,
	}
	ctx.Encode(response)
}

func (a *AccountAPI) register(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request RegisterRequest
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

func (a *AccountAPI) verifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request VerifyEmailRequest
	err := ctx.Decode(&request)
	if err != nil {
		return
	}

	if request.Email == "" || request.Token == "" {
		_ = ctx.Error(errors.New("invalid request"), http.StatusBadRequest)
		return
	}

	err = a.user_verify.VerifyEmail(request.Email, request.Token)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *AccountAPI) resendVerifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user := middleware.GetUserFromContext(r.Context())

	err := a.user_verify.SendEmailVerification(user)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *AccountAPI) otpGenerate(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user := middleware.GetUserFromContext(r.Context())

	otp, err := a.otp.OTPGenerate(user)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	response := &OTPGenerateResponse{
		OTP: otp,
	}
	ctx.Encode(response)
}

func (a *AccountAPI) otpVerify(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user := middleware.GetUserFromContext(r.Context())

	var request OTPVerifyRequest
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
func (a *AccountAPI) otpValidate(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user := middleware.GetUserFromContext(r.Context())

	var request OTPValidateRequest
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

	response := &LoginResponse{
		Token: jwt,
		Otp:   false,
	}
	ctx.Encode(response)
}
func (a *AccountAPI) otpDisable(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user := middleware.GetUserFromContext(r.Context())

	var request OTPDisableRequest
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
func (a *AccountAPI) passwordResetRequest(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request PasswordResetRequest
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

func (a *AccountAPI) passwordResetConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	var request PasswordResetVerifyRequest
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
func (a *AccountAPI) ping(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	token := middleware.GetAuthTokenFromContext(r.Context())
	core.EchoAuthCookie(w, r, a.ctx)
	core.SendJWT(w, token)

	response := &PongResponse{
		Ping:  "pong",
		Token: token,
	}
	ctx.Encode(response)
}

func (a *AccountAPI) accountInfo(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user := middleware.GetUserFromContext(r.Context())

	_, acct, err := a.user.AccountExists(user)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	response := &AccountInfoResponse{
		ID:        acct.ID,
		Email:     acct.Email,
		FirstName: acct.FirstName,
		LastName:  acct.LastName,
		Verified:  acct.Verified,
	}
	ctx.Encode(response)
}

func (a *AccountAPI) logout(w http.ResponseWriter, r *http.Request) {
	core.ClearAuthCookie(w, a.ctx)
	w.WriteHeader(http.StatusOK)
}

func (a *AccountAPI) uploadLimit(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	response := &UploadLimitResponse{
		Limit: a.config.Config().Core.PostUploadLimit,
	}
	ctx.Encode(response)
}

func (a *AccountAPI) updateEmail(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user := middleware.GetUserFromContext(r.Context())

	var request UpdateEmailRequest
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

func (a *AccountAPI) updatePassword(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user := middleware.GetUserFromContext(r.Context())

	var request UpdatePasswordRequest
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

func (a *AccountAPI) meta(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	response := &MetaResponse{
		Domain: a.config.Config().Core.Domain,
	}
	ctx.Encode(response)
}

func (a *AccountAPI) Configure(router *mux.Router) error {
	// CORS configuration
	corsOpts := cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}
	corsHandler := cors.New(corsOpts)

	// Middleware functions
	loginAuthMw2fa := authMiddleware(middleware.AuthMiddlewareOptions{
		Context:        a.ctx,
		Purpose:        core.JWTPurpose2FA,
		EmptyAllowed:   true,
		ExpiredAllowed: true,
	})

	authMw := authMiddleware(middleware.AuthMiddlewareOptions{
		Context: a.ctx,
		Purpose: core.JWTPurposeNone,
	})

	pingAuthMw := authMiddleware(middleware.AuthMiddlewareOptions{
		Context: a.ctx,
		Purpose: core.JWTPurposeLogin,
	})

	// Swagger routes
	err := swagger.Swagger(swagSpec, router)
	if err != nil {
		return err
	}

	// Routes
	router.HandleFunc("/api/upload-limit", a.uploadLimit).Methods("GET").Use(corsHandler.Handler)
	router.HandleFunc("/api/meta", a.meta).Methods("GET").Use(corsHandler.Handler)
	router.HandleFunc("/api/auth/register", a.register).Methods("POST").Use(corsHandler.Handler)
	router.HandleFunc("/api/account/password-reset/request", a.passwordResetRequest).Methods("POST").Use(corsHandler.Handler)
	router.HandleFunc("/api/account/password-reset/confirm", a.passwordResetConfirm).Methods("POST").Use(corsHandler.Handler)

	router.HandleFunc("/api/auth/otp/generate", a.otpGenerate).Methods("GET").Use(authMw, corsHandler.Handler)
	router.HandleFunc("/api/account", a.accountInfo).Methods("GET").Use(authMw, corsHandler.Handler)

	router.HandleFunc("/api/auth/ping", a.ping).Methods("POST").Use(pingAuthMw, corsHandler.Handler)
	router.HandleFunc("/api/auth/login", a.login).Methods("POST").Use(loginAuthMw2fa, corsHandler.Handler)
	router.HandleFunc("/api/auth/otp/validate", a.otpValidate).Methods("POST").Use(authMw, corsHandler.Handler)
	router.HandleFunc("/api/auth/logout", a.logout).Methods("POST").Use(authMw, corsHandler.Handler)

	router.HandleFunc("/api/account/verify-email", a.verifyEmail).Methods("POST").Use(authMw, corsHandler.Handler)
	router.HandleFunc("/api/account/verify-email/resend", a.resendVerifyEmail).Methods("POST").Use(authMw, corsHandler.Handler)
	router.HandleFunc("/api/account/otp/verify", a.otpVerify).Methods("POST").Use(authMw, corsHandler.Handler)
	router.HandleFunc("/api/account/otp/disable", a.otpDisable).Methods("POST").Use(authMw, corsHandler.Handler)
	router.HandleFunc("/api/account/update-email", a.updateEmail).Methods("POST").Use(authMw, corsHandler.Handler)
	router.HandleFunc("/api/account/update-password", a.updatePassword).Methods("POST").Use(authMw, corsHandler.Handler)

	// Catch-all route for client-side app
	router.PathPrefix("/").Handler(portal_dashboard.Handler())

	return nil
}

func (a *AccountAPI) Subdomain() string {
	return a.ctx.Config().Config().Core.AccountSubdomain
}

func (a *AccountAPI) AuthTokenName() string {
	return core.AUTH_COOKIE_NAME
}

func factory() core.PluginInfo {
	return core.PluginInfo{
		ID: "account",
		GetAPI: func(ctx *core.Context) (core.API, error) {
			return NewAccountAPI(*ctx), nil
		},
	}
}
