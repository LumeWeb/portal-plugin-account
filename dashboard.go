package account

import (
	"embed"
	_ "embed"
	"errors"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal/config"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/event"
	"go.lumeweb.com/portal/middleware"
	"go.lumeweb.com/portal/middleware/swagger"
	"go.lumeweb.com/portal/service"
	portal_dashboard "go.lumeweb.com/web/go/portal-dashboard"
	"go.uber.org/zap"
	"net/http"
	"net/url"
)

//go:embed swagger.yaml
var swagSpec []byte

//go:embed templates/*
var mailerTemplates embed.FS

var _ core.API = (*AccountAPI)(nil)

const pluginName = "dashboard"

func init() {
	templates, err := service.MailerTemplatesFromEmbed(&mailerTemplates, "")
	if err != nil {
		panic(err)
	}

	core.RegisterPlugin(core.PluginInfo{
		ID: pluginName,
		API: func() (core.API, []core.ContextBuilderOption, error) {
			return NewAccountAPI()
		},
		MailerTemplates: templates,
	})
}

type AccountAPI struct {
	ctx      core.Context
	config   config.Manager
	user     core.UserService
	auth     core.AuthService
	password core.PasswordResetService
	otp      core.OTPService
	logger   *core.Logger
}

func (a *AccountAPI) Config() config.APIConfig {
	return &APIConfig{}
}

func (a *AccountAPI) Name() string {
	return "account"
}

func NewAccountAPI() (*AccountAPI, []core.ContextBuilderOption, error) {
	api := &AccountAPI{}

	opts := core.ContextOptions(
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			api.ctx = ctx
			api.config = ctx.Config()
			api.user = ctx.Service(core.USER_SERVICE).(core.UserService)
			api.auth = ctx.Service(core.AUTH_SERVICE).(core.AuthService)
			api.password = ctx.Service(core.PASSWORD_RESET_SERVICE).(core.PasswordResetService)
			api.otp = ctx.Service(core.OTP_SERVICE).(core.OTPService)
			api.logger = ctx.Logger()

			return nil
		}),
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			e, ok := ctx.Event().GetEvent(event.EVENT_USER_SUBDOMAIN_SET)
			if !ok {
				return errors.New("event not found")
			}
			e.(*event.UserSubdomainSetEvent).SetSubdomain(api.Subdomain())
			err := ctx.Event().FireEvent(e)
			if err != nil {
				return err
			}
			return nil
		}),
	)

	return api, opts, nil
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

	rootDomain := "https://" + a.ctx.Config().Config().Core.Domain
	vals := url.Values{}
	vals.Add(a.AuthTokenName(), jwt)

	redirectURL := rootDomain + "/api/auth/complete?" + vals.Encode()

	http.Redirect(w, r, redirectURL, http.StatusFound)
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

	err = a.user.VerifyEmail(request.Email, request.Token)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *AccountAPI) resendVerifyEmail(w http.ResponseWriter, r *http.Request) {
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

func (a *AccountAPI) otpGenerate(w http.ResponseWriter, r *http.Request) {
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

	response := &OTPGenerateResponse{
		OTP: otp,
	}
	ctx.Encode(response)
}

func (a *AccountAPI) otpVerify(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)

	if !ok {
		return

	}

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
	user, ok := a.getUser(ctx)

	if !ok {
		return
	}

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
	user, ok := a.getUser(ctx)

	if !ok {
		return
	}

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

	token, ok := a.getAuthToken(ctx)

	if !ok {
		return
	}

	core.EchoAuthCookie(w, r, a.ctx)
	core.SendJWT(w, token)

	response := &PongResponse{
		Ping:  "pong",
		Token: token,
	}
	ctx.Encode(response)
}

func (a *AccountAPI) rootAuthComplete(w http.ResponseWriter, r *http.Request) {
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

	response := &LoginResponse{
		Token: token,
		Otp:   user.OTPEnabled && user.OTPVerified,
	}

	ctx.Encode(response)
}

func (a *AccountAPI) accountInfo(w http.ResponseWriter, r *http.Request) {
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
	user, ok := a.getUser(ctx)

	if !ok {
		return
	}

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
	user, ok := a.getUser(ctx)

	if !ok {
		return
	}

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

func (a *AccountAPI) getUser(ctx httputil.RequestContext) (uint, bool) {
	user, err := middleware.GetUserFromContext(ctx)

	if err != nil {
		_ = ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
		return 0, false
	}

	return user, true
}

func (a *AccountAPI) getAuthToken(ctx httputil.RequestContext) (string, bool) {
	token, err := middleware.GetAuthTokenFromContext(ctx)

	if err != nil {
		_ = ctx.Error(core.NewAccountError(core.ErrKeyInvalidLogin, nil), http.StatusUnauthorized)
		return "", false
	}

	return token, true
}

func (a *AccountAPI) Configure(router *mux.Router) error {
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

	router.Use(corsHandler.Handler)

	// Routes
	router.HandleFunc("/api/upload-limit", a.uploadLimit).Methods("GET").Use(corsHandler.Handler)
	router.HandleFunc("/api/meta", a.meta).Methods("GET").Use(corsHandler.Handler)
	router.HandleFunc("/api/auth/register", a.register).Methods("POST").Use(corsHandler.Handler)
	router.HandleFunc("/api/account/password-reset/request", a.passwordResetRequest).Methods("POST").Use(corsHandler.Handler)
	router.HandleFunc("/api/account/password-reset/confirm", a.passwordResetConfirm).Methods("POST").Use(corsHandler.Handler)

	router.HandleFunc("/api/auth/otp/generate", a.otpGenerate).Methods("GET").Use(authMw)
	router.HandleFunc("/api/account", a.accountInfo).Methods("GET").Use(authMw)

	router.HandleFunc("/api/auth/ping", a.ping).Methods("POST").Use(pingAuthMw)
	router.HandleFunc("/api/auth/login", a.login).Methods("POST").Use(loginAuthMw2fa, corsHandler.Handler)
	router.HandleFunc("/api/auth/otp/validate", a.otpValidate).Methods("POST").Use(authMw)
	router.HandleFunc("/api/auth/logout", a.logout).Methods("POST").Use(authMw)

	router.HandleFunc("/api/account/verify-email", a.verifyEmail).Methods("POST").Use(authMw)
	router.HandleFunc("/api/account/verify-email/resend", a.resendVerifyEmail).Methods("POST").Use(authMw)
	router.HandleFunc("/api/account/otp/verify", a.otpVerify).Methods("POST").Use(authMw)
	router.HandleFunc("/api/account/otp/disable", a.otpDisable).Methods("POST").Use(authMw)
	router.HandleFunc("/api/account/update-email", a.updateEmail).Methods("POST").Use(authMw)
	router.HandleFunc("/api/account/update-password", a.updatePassword).Methods("POST").Use(authMw)

	// Catch-all route for client-side app
	router.PathPrefix("/assets/").Handler(portal_dashboard.Handler())
	router.PathPrefix("/").Handler(portal_dashboard.Handler()).Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Path = "/"
			next.ServeHTTP(w, r)
		})
	})

	rootRouter := core.GetService[core.HTTPService](a.ctx, core.HTTP_SERVICE).Router().Host(a.ctx.Config().Config().Core.Domain).Subrouter()

	rootRouter.Use(pingAuthMw)
	rootRouter.Use(corsHandler.Handler)

	rootRouter.HandleFunc("/api/auth/complete", a.rootAuthComplete).Methods("GET", "OPTIONS")

	return nil
}

func (a *AccountAPI) Subdomain() string {
	return a.ctx.Config().GetAPI(pluginName).(*APIConfig).Subdomain
}

func (a *AccountAPI) AuthTokenName() string {
	return core.AUTH_COOKIE_NAME
}
