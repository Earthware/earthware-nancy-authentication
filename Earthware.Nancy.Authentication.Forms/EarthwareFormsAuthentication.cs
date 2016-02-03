namespace Earthware.Nancy.Authentication.Forms
{
    using System;

    using global::Nancy;
    using global::Nancy.Authentication.Forms;
    using global::Nancy.Bootstrapper;
    using global::Nancy.Cookies;
    using global::Nancy.Helpers;

    /// <summary>
    ///     Forms Authentication implementation that builds on the default Nancy.Authentication.Forms namespace
    ///     but adds transient AuthSessionIds to make it impossible to reuse auth cookies between sessions.
    /// </summary>
    public static class EarthwareFormsAuthentication
    {
        private static EarthwareFormsAuthenticationConfiguration configuration;

        /// <summary>
        ///     Gets or sets the forms authentication cookie name
        /// </summary>
        public static string FormsAuthenticationCookieName
        {
            get
            {
                return FormsAuthentication.FormsAuthenticationCookieName;
            }

            set
            {
                FormsAuthentication.FormsAuthenticationCookieName = value;
            }
        }

        /// <summary>
        ///     Gets or sets the current configuration
        /// </summary>
        public static EarthwareFormsAuthenticationConfiguration Configuration
        {
            get
            {
                return configuration;
            }

            set
            {
                // If necessary, wrap the supplied user mapper in the session aware user mapper.
                if (!(value.UserMapper is AuthSessionIdUserMapper))
                {
                    value.UserMapper = new AuthSessionIdUserMapper(value.UserMapper, value.AuthSessionIdStore);
                }

                configuration = value;
            }
        }

        /// <summary>
        ///     Enables forms authentication for the application
        /// </summary>
        /// <param name="pipelines">Pipelines to add handlers to (usually "this")</param>
        /// <param name="configuration">Forms authentication configuration</param>
        public static void Enable(IPipelines pipelines, EarthwareFormsAuthenticationConfiguration configuration)
        {
            Configuration = configuration;
            FormsAuthentication.Enable(pipelines, Configuration);

            if (configuration.SlidingSessionExpirationMinutes.HasValue)
            {
                pipelines.AfterRequest.AddItemToEndOfPipeline(GetUpdateSessionExpiryHook());
            }
        }

        /// <summary>
        ///     Enables forms authentication for a module
        /// </summary>
        /// <param name="module">Module to add handlers to (usually "this")</param>
        /// <param name="configuration">Forms authentication configuration</param>
        public static void Enable(INancyModule module, EarthwareFormsAuthenticationConfiguration configuration)
        {
            Configuration = configuration;
            FormsAuthentication.Enable(module, Configuration);

            if (configuration.SlidingSessionExpirationMinutes.HasValue)
            {
                module.After.AddItemToEndOfPipeline(GetUpdateSessionExpiryHook());
            }
        }

        /// <summary>
        ///     Logs the user in.
        /// </summary>
        /// <param name="userIdentifier">User identifier guid</param>
        /// <param name="cookieExpiry">Optional expiry date for the cookie (for 'Remember me')</param>
        /// <returns>Nancy response with status <see cref="HttpStatusCode.OK" /></returns>
        public static Response UserLoggedInResponse(Guid userIdentifier, DateTime? cookieExpiry = null)
        {
            var authSessionId = Configuration.AuthSessionIdStore.Add(
                userIdentifier,
                GetAuthSessionStoreExpiryTime(cookieExpiry));

            return FormsAuthentication.UserLoggedInResponse(authSessionId, cookieExpiry);
        }

        /// <summary>
        ///     Creates a response that sets the authentication cookie and redirects
        ///     the user back to where they came from.
        /// </summary>
        /// <param name="context">Current context</param>
        /// <param name="userIdentifier">User identifier guid</param>
        /// <param name="cookieExpiry">Optional expiry date for the cookie (for 'Remember me')</param>
        /// <param name="fallbackRedirectUrl">Url to redirect to if none in the querystring</param>
        /// <returns>Nancy response with redirect.</returns>
        public static Response UserLoggedInRedirectResponse(
            NancyContext context,
            Guid userIdentifier,
            DateTime? cookieExpiry = null,
            string fallbackRedirectUrl = null)
        {
            var authSessionId = Configuration.AuthSessionIdStore.Add(
                userIdentifier,
                GetAuthSessionStoreExpiryTime(cookieExpiry));

            return FormsAuthentication.UserLoggedInRedirectResponse(
                context,
                authSessionId,
                cookieExpiry,
                fallbackRedirectUrl);
        }

        /// <summary>
        ///     Logs the user out and redirects them to a URL
        /// </summary>
        /// <param name="context">Current context</param>
        /// <param name="redirectUrl">URL to redirect to</param>
        /// <returns>Nancy response</returns>
        public static Response LogOutAndRedirectResponse(NancyContext context, string redirectUrl)
        {
            RemoveSessionIdFromStore(context);

            return FormsAuthentication.LogOutAndRedirectResponse(context, redirectUrl);
        }

        /// <summary>
        ///     Logs the user out.
        /// </summary>
        /// <returns>Nancy response</returns>
        public static Response LogOutResponse(NancyContext context)
        {
            RemoveSessionIdFromStore(context);

            return FormsAuthentication.LogOutResponse();
        }

        /// <summary>
        ///     Decrypt and validate an encrypted and signed cookie value
        /// </summary>
        /// <param name="cookieValue">Encrypted and signed cookie value</param>
        /// <param name="configuration">Current configuration</param>
        /// <returns>Decrypted value, or empty on error or if failed validation</returns>
        public static string DecryptAndValidateAuthenticationCookie(
            string cookieValue,
            EarthwareFormsAuthenticationConfiguration configuration)
        {
            return FormsAuthentication.DecryptAndValidateAuthenticationCookie(cookieValue, configuration);
        }

        /// <summary>
        ///     Retrieves the function that will update the expiry time on the auth cookie and the
        ///     server side auth session Id store.
        /// </summary>
        /// <returns></returns>
        private static Action<NancyContext> GetUpdateSessionExpiryHook()
        {
            if (Configuration == null)
            {
                throw new ArgumentNullException(nameof(Configuration));
            }

            return context =>
                {
                    var shouldExtendAuthSessionExpiry = configuration.SlidingSessionExpirationMinutes.HasValue
                                                        && context.Request.Cookies.ContainsKey(
                                                            FormsAuthenticationCookieName)
                                                        && !context.Request.Path.Contains(Configuration.LogoutPath)
                                                        && context.CurrentUser != null;

                    if (shouldExtendAuthSessionExpiry)
                    {
                        var cookieValueEncrypted = GetEncryptedCookieValue(context);
                        var authSessionId = GetAuthSessionIdFromEncryptedCookieValue(cookieValueEncrypted);

                        if (authSessionId == Guid.Empty)
                        {
                            return;
                        }

                        var expires = DateTime.UtcNow.AddMinutes(configuration.SlidingSessionExpirationMinutes.Value);

                        var newCookie = new NancyCookie(
                            FormsAuthenticationCookieName,
                            HttpUtility.UrlDecode(cookieValueEncrypted),
                            true,
                            configuration.RequiresSSL,
                            expires);

                        context.Response.WithCookie(newCookie);

                        // Also update the cache entry to keep consistent
                        configuration.AuthSessionIdStore.Extend(authSessionId, expires);
                    }
                };
        }

        /// <summary>
        ///     Retreives the encrypted cookie value. Note that the value will be UrlEncoded.
        /// </summary>
        /// <param name="context">Nancy context for the current request</param>
        /// <returns>The url-encoded value of the forms auth cookie</returns>
        private static string GetEncryptedCookieValue(NancyContext context)
        {
            return context.Request.Cookies[FormsAuthenticationCookieName];
        }

        /// <summary>
        ///     Given the Url-encoded cookie value, returns the auth session id.
        /// </summary>
        /// <param name="encryptedCookieValue"></param>
        /// <returns></returns>
        private static Guid GetAuthSessionIdFromEncryptedCookieValue(string encryptedCookieValue)
        {
            if (string.IsNullOrEmpty(encryptedCookieValue))
            {
                return Guid.Empty;
            }

            var cookieValue = FormsAuthentication.DecryptAndValidateAuthenticationCookie(
                encryptedCookieValue,
                Configuration);

            Guid authSessionId;

            if (string.IsNullOrEmpty(cookieValue) || !Guid.TryParse(cookieValue, out authSessionId))
            {
                return Guid.Empty;
            }

            return authSessionId;
        }

        /// <summary>
        ///     Retrieve  the auth session id from the forms auth cookie.
        /// </summary>
        /// <param name="context">Nancy context for the current request</param>
        /// <returns>The auth session Id, or Guid.Empty if none exists.</returns>
        private static Guid GetAuthSessionIdFromCookie(NancyContext context)
        {
            return GetAuthSessionIdFromEncryptedCookieValue(GetEncryptedCookieValue(context));
        }

        /// <summary>
        ///     Returns the appropriate expiry time for the auth session, based on the user's input and the configuration options.
        ///     If the user has supplied an expiry date, it's used. Otherwise if the configuration specifies sliding expiration,
        ///     that value is used to calculate the expiration date.
        /// </summary>
        /// <param name="suppliedValue">The value that was supplied by the user for the cookie expiration time.</param>
        /// <returns>The time to use when adding the auth session id to the auth session store.</returns>
        private static DateTime GetAuthSessionStoreExpiryTime(DateTime? suppliedValue)
        {
            if (suppliedValue.HasValue)
            {
                return suppliedValue.Value;
            }

            if (Configuration.SlidingSessionExpirationMinutes.HasValue)
            {
                return DateTime.UtcNow.AddMinutes(Configuration.SlidingSessionExpirationMinutes.Value);
            }

            // If no expiry time could be found, make the session valid until midnight.
            return DateTime.UtcNow.AddDays(1).Date;
        }

        private static void RemoveSessionIdFromStore(NancyContext context)
        {
            var authSessionId = GetAuthSessionIdFromCookie(context);

            if (authSessionId != Guid.Empty)
            {
                Configuration.AuthSessionIdStore.Remove(authSessionId);
            }
        }
    }
}