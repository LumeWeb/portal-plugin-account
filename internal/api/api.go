package api

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/rs/cors"
	"github.com/samber/lo"
	"github.com/sethvargo/go-password/password"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/messages"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	_ "go.lumeweb.com/portal-plugin-dashboard/internal/provider/providers"
	"go.lumeweb.com/portal-plugin-dashboard/internal/service"
	"go.lumeweb.com/portal/config"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/event"
	"go.lumeweb.com/portal/middleware"
	"go.lumeweb.com/portal/middleware/swagger"
	portal_dashboard "go.lumeweb.com/web/go/portal-dashboard"
	"go.uber.org/zap"
	"golang.org/x/crypto/hkdf"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const returnSessionKey = "return"

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
	apiKey   service.APIKeyService
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
			api.apiKey = ctx.Service(service.API_KEY_SERVICE).(service.APIKeyService)
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

		core.ContextWithStartupFunc(func(ctx core.Context) error {
			pluginCfg := ctx.Config().GetAPI(internal.PLUGIN_NAME).(*pluginConfig.APIConfig)

			if pluginCfg.SocialLogin.Enabled {
				authCookieKey, err := generateSocialKey(ctx, "auth")
				if err != nil {
					return err
				}

				encCookieKey, err := generateSocialKey(ctx, "encrypt")
				if err != nil {
					return err
				}

				cookieStore := sessions.NewCookieStore(authCookieKey, encCookieKey)
				cookieStore.Options.HttpOnly = true
				gothic.Store = cookieStore

				for _provider, providerConfig := range pluginCfg.SocialLogin.Provider {
					if !providerConfig.Enabled || !provider.ProviderExists(_provider) {
						continue
					}

					provider.ConfigureProvider(_provider, providerConfig)
				}

				if pluginCfg.SocialLogin.Order != nil && len(pluginCfg.SocialLogin.Order) > 0 {
					provider.SetProviderOrder(lo.Filter(pluginCfg.SocialLogin.Order, func(item string, _ int) bool {
						return provider.ProviderExists(item)
					}))
				}

				provider.Provider().SetContext(ctx)

				for _, providerId := range provider.EnabledProviders() {
					_provider, err := provider.CreateProvider(providerId)
					if err != nil {
						return err
					}
					goth.UseProviders(_provider)
				}
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
		_ = ctx.Error(err, err.HttpStatus())
		if err != nil {
			a.logger.Error("failed to login", zap.Error(err))
		}
		return
	}

	if user.OTPEnabled {
		response := &messages.LoginResponse{
			Token: jwt,
			Otp:   true,
		}
		ctx.Encode(response)
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
		if errors.Is(err, core.ErrInvalidOTPCode) {
			err := core.NewAccountError(core.ErrKeyInvalidOTPCode, nil)
			_ = ctx.Error(err, core.ErrorCodeToHttpStatus[core.ErrKeyInvalidOTPCode])
			return
		}

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

	rootDomain := "https://" + a.ctx.Config().Config().Core.Domain
	vals := url.Values{}
	vals.Add(a.AuthTokenName(), jwt)

	redirectURL := rootDomain + "/api/auth/complete?" + vals.Encode()

	http.Redirect(w, r, redirectURL, http.StatusFound)
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

	returnUrl := r.URL.Query().Get("return")

	core.SetAuthCookie(w, a.ctx, token)
	core.SendJWT(w, token)

	if len(returnUrl) > 0 {
		http.Redirect(w, r, returnUrl, http.StatusFound)
		return
	}

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
		OTP:       acct.OTPEnabled,
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

func (a *API) socialAuthLogin(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	returnUrl := r.URL.Query().Get(returnSessionKey)

	if returnUrl == "" {
		_ = ctx.Error(errors.New("return missing"), http.StatusBadRequest)
		return
	}

	err := gothic.StoreInSession(returnSessionKey, returnUrl, r, w)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	if gothUser, err := gothic.CompleteUserAuth(w, r); err == nil {
		a.setupOrLoginSocialUser(&gothUser, &ctx, returnUrl)
		w.WriteHeader(http.StatusOK)
		return
	}

	gothic.BeginAuthHandler(w, r)
}

func (a *API) socialAuthCallback(w http.ResponseWriter, r *http.Request) {
	returnUrl, err := gothic.GetFromSession(returnSessionKey, r)
	if err != nil {
		_ = httputil.Context(r, w).Error(err, http.StatusInternalServerError)
		return
	}

	gothUser, err := gothic.CompleteUserAuth(w, r)
	ctx := httputil.Context(r, w)

	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	a.setupOrLoginSocialUser(&gothUser, &ctx, returnUrl)
}

func (a *API) socialAuthLogout(w http.ResponseWriter, r *http.Request) {
	err := gothic.Logout(w, r)
	if err != nil {
		_ = httputil.Context(r, w).Error(err, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func (a *API) setupOrLoginSocialUser(guser *goth.User, ctx *httputil.RequestContext, returnUrl string) {
	exists, m, err := a.user.EmailExists(guser.Email)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	if !exists {
		pw, err := password.Generate(64, 10, 10, false, false)
		if err != nil {
			_ = ctx.Error(err, http.StatusInternalServerError)
			return
		}

		user, err := a.user.CreateAccount(guser.Email, pw, false)
		if err != nil {
			_ = ctx.Error(err, http.StatusInternalServerError)
			return
		}

		err = a.user.UpdateAccountName(user.ID, user.FirstName, user.LastName)
		if err != nil {
			_ = ctx.Error(err, http.StatusInternalServerError)
			return
		}
	}

	jwt, err := a.auth.LoginID(m.ID, ctx.Request.RemoteAddr)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	rootDomain := "https://" + a.ctx.Config().Config().Core.Domain
	vals := url.Values{}
	vals.Add(a.AuthTokenName(), jwt)
	vals.Add("return", returnUrl)

	redirectURL := rootDomain + "/api/auth/complete?" + vals.Encode()

	http.Redirect(ctx.Response, ctx.Request, redirectURL, http.StatusFound)
}

func (a *API) createAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)
	if !ok {
		return
	}

	var request messages.APIKeyCreateRequest
	if err := ctx.Decode(&request); err != nil {
		return
	}

	apiKey, err := a.apiKey.CreateAPIKey(user, request.Name)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	ctx.Encode(apiKey)
}

func (a *API) getAPIKeys(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)
	if !ok {
		return
	}

	query := r.URL.Query()

	// Parse pagination
	pagination := &service.Pagination{
		Page:     1,
		PageSize: 10,
	}
	if page := query.Get("_page"); page != "" {
		pagination.Page, _ = strconv.Atoi(page)
	}
	if pageSize := query.Get("_limit"); pageSize != "" {
		pagination.PageSize, _ = strconv.Atoi(pageSize)
	}

	// Parse filters
	filters := make(map[string]interface{})
	for key, values := range query {
		if !strings.HasPrefix(key, "_") && len(values) > 0 {
			filters[key] = values[0]
		}
	}

	// Parse sorters
	var sorters []service.Sorter
	if sort := query.Get("_sort"); sort != "" {
		sortFields := strings.Split(sort, ",")
		sortOrders := strings.Split(query.Get("_order"), ",")
		for i, field := range sortFields {
			order := "asc"
			if i < len(sortOrders) {
				order = sortOrders[i]
			}
			sorters = append(sorters, service.Sorter{Field: field, Order: order})
		}
	}

	result, err := a.apiKey.GetAPIKeys(user, pagination, filters, sorters)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.Header().Set("X-Total-Count", fmt.Sprintf("%d", result.Total))
	ctx.Encode(result.Data)
}

func (a *API) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)
	if !ok {
		return
	}

	vars := mux.Vars(r)
	keyID, err := uuid.Parse(vars["keyID"])
	if err != nil {
		_ = ctx.Error(errors.New("invalid key ID"), http.StatusBadRequest)
		return
	}

	err = a.apiKey.DeleteAPIKey(user, keyID)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *API) authWithAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)

	token := middleware.ParseAuthTokenHeader(ctx.Request.Header)

	if token == "" {
		_ = ctx.Error(errors.New("missing Authorization header"), http.StatusUnauthorized)
		return
	}

	validatedKey, err := a.apiKey.ValidateAPIKey(token)
	if err != nil {
		_ = ctx.Error(errors.New("invalid API key"), http.StatusUnauthorized)
		return
	}

	jwt, err := a.auth.LoginID(validatedKey.UserID, r.RemoteAddr)
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	response := &messages.LoginResponse{
		Token: jwt,
	}

	ctx.Encode(response)
}

func (a *API) deleteAccount(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	user, ok := a.getUser(ctx)

	if !ok {
		return
	}

	err := a.user.RequestAccountDeletion(user, ctx.Request.RemoteAddr)
	if err != nil {
		if core.IsAccountError(err) && core.AsAccountError(err).IsErrorType(core.ErrKeyAccountDeletionRequestAlreadyExists) {
			_ = ctx.Error(err, core.AsAccountError(err).HttpStatus())
			return

		}
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	core.ClearAuthCookie(w, a.ctx)
	w.WriteHeader(http.StatusOK)
}

func (a *API) Configure(router *mux.Router) error {
	pluginCfg := a.config.GetAPI(internal.PLUGIN_NAME).(*pluginConfig.APIConfig)
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
		EmptyAllowed:   false,
		ExpiredAllowed: false,
	})

	authMw := middleware.AuthMiddleware(middleware.AuthMiddlewareOptions{
		Context: a.ctx,
		Purpose: core.JWTPurposeLogin,
	})

	// Swagger routes
	err := swagger.Swagger(swagSpec, router)
	if err != nil {
		return err
	}

	router.Use(corsHandler.Handler)

	// Authentication routes
	router.HandleFunc("/api/auth/register", a.register).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/auth/login", a.login).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/auth/logout", a.logout).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/auth/ping", a.ping).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/auth/key", a.authWithAPIKey).Methods("POST", "OPTIONS")

	// OTP routes
	router.HandleFunc("/api/auth/otp/generate", a.otpGenerate).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/auth/otp/validate", a.otpValidate).Methods("POST", "OPTIONS").Use(loginAuthMw2fa)
	router.HandleFunc("/api/auth/otp/verify", a.otpVerify).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/auth/otp/disable", a.otpDisable).Methods("POST", "OPTIONS").Use(authMw)

	// Account routes
	router.HandleFunc("/api/account", a.accountInfo).Methods("GET", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/account/verify-email", a.verifyEmail).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/account/verify-email/resend", a.resendVerifyEmail).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/account/update-email", a.updateEmail).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/account/update-password", a.updatePassword).Methods("POST", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/account/password-reset/request", a.passwordResetRequest).Methods("POST")
	router.HandleFunc("/api/account/password-reset/confirm", a.passwordResetConfirm).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/account/delete", a.deleteAccount).Methods("DELETE", "OPTIONS").Use(authMw)

	// API Key routes
	apiKeyRouter := router.PathPrefix("/api/account/keys").Subrouter()
	apiKeyRouter.Use(authMw)
	apiKeyRouter.HandleFunc("", a.createAPIKey).Methods("POST", "OPTIONS")
	apiKeyRouter.HandleFunc("", a.getAPIKeys).Methods("GET", "OPTIONS")
	apiKeyRouter.HandleFunc("/{keyID}", a.deleteAPIKey).Methods("DELETE", "OPTIONS")

	// Other routes
	router.HandleFunc("/api/upload-limit", a.uploadLimit).Methods("GET", "OPTIONS")

	if pluginCfg.SocialLogin.Enabled {
		a.setupSocialAuthRoutes(router)
	}

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

	rootRouter.Use(authMw)
	rootRouter.Use(corsHandler.Handler)

	rootRouter.HandleFunc("/api/auth/complete", a.rootAuthComplete).Methods("GET", "OPTIONS")
	return nil
}

func (a *API) setupSocialAuthRoutes(router *mux.Router) {
	router.HandleFunc("/api/account/auth/sso/{provider}", a.socialAuthLogin).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/account/auth/sso/{provider}/callback", a.socialAuthCallback).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/account/auth/sso/{provider}/logout", a.socialAuthLogout).Methods("GET", "OPTIONS")
}

func (a *API) Subdomain() string {
	return a.ctx.Config().GetAPI(internal.PLUGIN_NAME).(*pluginConfig.APIConfig).Subdomain
}

func (a *API) AuthTokenName() string {
	return core.AUTH_COOKIE_NAME
}

func generateSocialKey(ctx core.Context, kind string) ([]byte, error) {
	hasher := hkdf.New(sha256.New, ctx.Config().Config().Core.Identity.PrivateKey(), ctx.Config().Config().Core.NodeID.Bytes(), []byte(fmt.Sprintf("%s-%s", internal.PLUGIN_NAME, fmt.Sprintf("social-login-%s", kind))))
	derivedSeed := make([]byte, 32)

	if _, err := io.ReadFull(hasher, derivedSeed); err != nil {
		return nil, fmt.Errorf("failed to generate child key seed: %w", err)
	}

	return derivedSeed, nil
}
