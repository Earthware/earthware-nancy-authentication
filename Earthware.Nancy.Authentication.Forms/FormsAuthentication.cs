namespace Earthware.Nancy.Authentication.Forms
{
    using System;

    using global::Nancy;
    using global::Nancy.Bootstrapper;
    using global::Nancy.Cookies;
    using global::Nancy.Cryptography;
    using global::Nancy.Extensions;
    using global::Nancy.Helpers;

    /// <summary>
    ///     Nancy forms authentication implementation
    /// </summary>
    public static class FormsAuthentication
    {
        public const string AuthSessionIdItemKey = "Earthware.Nancy.FormsAuthentication.AuthSessionIdItemKey";

        public const string UserLoggedOutKey = "Earthware.Nancy.FormsAuthentication.UserLoggedOutKey";

        // TODO - would prefer not to hold this here, but the redirect response needs it
        private static FormsAuthenticationConfiguration currentConfiguration;

        /// <summary>
        ///     Gets or sets the forms authentication cookie name
        /// </summary>
        public static string FormsAuthenticationCookieName { get; set; } = "_ncfa";

        /// <summary>
        ///     Decrypt and validate an encrypted and signed cookie value
        /// </summary>
        /// <param name="decodedCookieValue">Encrypted and signed cookie value</param>
        /// <param name="configuration">Current configuration</param>
        /// <returns>Decrypted value, or empty on error or if failed validation</returns>
        public static string DecryptAndValidateAuthenticationCookie(
            string decodedCookieValue,
            FormsAuthenticationConfiguration configuration)
        {
            var hmacStringLength =
                Base64Helpers.GetBase64Length(configuration.CryptographyConfiguration.HmacProvider.HmacLength);

            var encryptedCookie = decodedCookieValue.Substring(hmacStringLength);
            var hmacString = decodedCookieValue.Substring(0, hmacStringLength);

            var encryptionProvider = configuration.CryptographyConfiguration.EncryptionProvider;

            // Check the hmacs, but don't early exit if they don't match
            var hmacBytes = Convert.FromBase64String(hmacString);
            var newHmac = GenerateHmac(encryptedCookie, configuration);
            var hmacValid = HmacComparer.Compare(
                newHmac,
                hmacBytes,
                configuration.CryptographyConfiguration.HmacProvider.HmacLength);

            var decrypted = encryptionProvider.Decrypt(encryptedCookie);

            // Only return the decrypted result if the hmac was ok
            return hmacValid ? decrypted : string.Empty;
        }

        /// <summary>
        ///     Enables forms authentication for the application
        /// </summary>
        /// <param name="pipelines">Pipelines to add handlers to (usually "this")</param>
        /// <param name="configuration">Forms authentication configuration</param>
        public static void Enable(IPipelines pipelines, FormsAuthenticationConfiguration configuration)
        {
            if (pipelines == null)
            {
                throw new ArgumentNullException(nameof(pipelines));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration.Validate();

            currentConfiguration = configuration;

            pipelines.BeforeRequest.AddItemToStartOfPipeline(GetLoadAuthenticationHook(configuration));

            if (!configuration.DisableRedirect)
            {
                pipelines.AfterRequest.AddItemToEndOfPipeline(GetRedirectToLoginHook(configuration));
            }

            pipelines.AfterRequest.AddItemToEndOfPipeline(GetUpdateSessionCookieHook(configuration));
        }

        /// <summary>
        ///     Logs the user out and redirects them to a URL
        /// </summary>
        /// <param name="context">Current context</param>
        /// <param name="redirectUrl">URL to redirect to</param>
        /// <returns>Nancy response</returns>
        public static Response LogOutAndRedirectResponse(NancyContext context, string redirectUrl)
        {
            var response = context.GetRedirect(redirectUrl);

            var authenticationCookie = BuildLogoutCookie(currentConfiguration);

            response.WithCookie(authenticationCookie);

            context.Items[UserLoggedOutKey] = new object();
            context.CurrentUser = null;

            if (context.Items.ContainsKey(AuthSessionIdItemKey))
            {
                currentConfiguration.AuthSessionIdStore.Remove((Guid)context.Items[AuthSessionIdItemKey]);
            }

            return response;
        }

        /// <summary>
        ///     Logs the user out.
        /// </summary>
        /// <returns>Nancy response</returns>
        public static Response LogOutResponse(NancyContext context)
        {
            var response = (Response)HttpStatusCode.OK;

            var authenticationCookie = BuildLogoutCookie(currentConfiguration);

            response.WithCookie(authenticationCookie);

            context.Items[UserLoggedOutKey] = new object();
            context.CurrentUser = null;

            if (context.Items.ContainsKey(AuthSessionIdItemKey))
            {
                currentConfiguration.AuthSessionIdStore.Remove((Guid)context.Items[AuthSessionIdItemKey]);
            }

            return response;
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
            var redirectUrl = fallbackRedirectUrl;

            if (string.IsNullOrEmpty(redirectUrl))
            {
                redirectUrl = context.Request.Url.BasePath;
            }

            if (string.IsNullOrEmpty(redirectUrl))
            {
                redirectUrl = "/";
            }

            var redirectQuerystringKey = GetRedirectQuerystringKey(currentConfiguration);

            if (context.Request.Query[redirectQuerystringKey].HasValue)
            {
                var queryUrl = (string)context.Request.Query[redirectQuerystringKey];

                if (context.IsLocalUrl(queryUrl))
                {
                    redirectUrl = queryUrl;
                }
            }

            var response = context.GetRedirect(redirectUrl);
            var authenticationCookie = BuildCookie(userIdentifier, currentConfiguration);
            response.WithCookie(authenticationCookie);

            return response;
        }

        /// <summary>
        ///     Logs the user in.
        /// </summary>
        /// <param name="userIdentifier">User identifier guid</param>
        /// <param name="cookieExpiry">Optional expiry date for the cookie (for 'Remember me')</param>
        /// <returns>Nancy response with status <see cref="HttpStatusCode.OK" /></returns>
        public static Response UserLoggedInResponse(Guid userIdentifier, DateTime? cookieExpiry = null)
        {
            var response = (Response)HttpStatusCode.OK;

            var authenticationCookie = BuildCookie(userIdentifier, currentConfiguration);

            response.WithCookie(authenticationCookie);

            return response;
        }

        /// <summary>
        ///     Build the forms authentication cookie
        /// </summary>
        /// <param name="userIdentifier">Authenticated user identifier</param>
        /// <param name="cookieExpiry">Optional expiry date for the cookie (for 'Remember me')</param>
        /// <param name="configuration">Current configuration</param>
        /// <returns>Nancy cookie instance</returns>
        private static INancyCookie BuildCookie(Guid userIdentifier, FormsAuthenticationConfiguration configuration)
        {
            var expiryTime = DateTime.UtcNow.AddMinutes(configuration.SlidingSessionExpirationMinutes);

            var authSessionId = configuration.AuthSessionIdStore.Add(userIdentifier, expiryTime);

            var cookieContents = EncryptAndSignCookie(authSessionId.ToString(), configuration);

            var cookie = new NancyCookie(FormsAuthenticationCookieName, cookieContents, true, configuration.RequiresSSL)
                             {
                                 Expires = expiryTime
                             };

            if (!string.IsNullOrEmpty(configuration.Domain))
            {
                cookie.Domain = configuration.Domain;
            }

            if (!string.IsNullOrEmpty(configuration.Path))
            {
                cookie.Path = configuration.Path;
            }

            return cookie;
        }

        /// <summary>
        ///     Builds a cookie for logging a user out
        /// </summary>
        /// <param name="configuration">Current configuration</param>
        /// <returns>Nancy cookie instance</returns>
        private static INancyCookie BuildLogoutCookie(FormsAuthenticationConfiguration configuration)
        {
            var cookie = new NancyCookie(FormsAuthenticationCookieName, string.Empty, true, configuration.RequiresSSL)
                             {
                                 Expires = DateTime.Now.AddDays(-1)
                             };

            if (!string.IsNullOrEmpty(configuration.Domain))
            {
                cookie.Domain = configuration.Domain;
            }

            if (!string.IsNullOrEmpty(configuration.Path))
            {
                cookie.Path = configuration.Path;
            }

            return cookie;
        }

        /// <summary>
        ///     Encrypt and sign the cookie contents
        /// </summary>
        /// <param name="cookieValue">Plain text cookie value</param>
        /// <param name="configuration">Current configuration</param>
        /// <returns>Encrypted and signed string</returns>
        private static string EncryptAndSignCookie(string cookieValue, FormsAuthenticationConfiguration configuration)
        {
            var encryptedCookie = configuration.CryptographyConfiguration.EncryptionProvider.Encrypt(cookieValue);
            var hmacBytes = GenerateHmac(encryptedCookie, configuration);
            var hmacString = Convert.ToBase64String(hmacBytes);

            return string.Format("{1}{0}", encryptedCookie, hmacString);
        }

        /// <summary>
        ///     Generate a hmac for the encrypted cookie string
        /// </summary>
        /// <param name="encryptedCookie">Encrypted cookie string</param>
        /// <param name="configuration">Current configuration</param>
        /// <returns>Hmac byte array</returns>
        private static byte[] GenerateHmac(string encryptedCookie, FormsAuthenticationConfiguration configuration)
        {
            return configuration.CryptographyConfiguration.HmacProvider.GenerateHmac(encryptedCookie);
        }

        /// <summary>
        ///     Gets the authenticated user GUID from the incoming request cookie if it exists
        ///     and is valid.
        /// </summary>
        /// <param name="context">Current context</param>
        /// <param name="configuration">Current configuration</param>
        /// <returns>Returns user guid, or Guid.Empty if not present or invalid</returns>
        private static Guid GetAuthenticatedUserFromCookie(
            NancyContext context,
            FormsAuthenticationConfiguration configuration)
        {
            if (!context.Request.Cookies.ContainsKey(FormsAuthenticationCookieName))
            {
                return Guid.Empty;
            }

            if (string.IsNullOrWhiteSpace(context.Request.Cookies[FormsAuthenticationCookieName]))
            {
                return Guid.Empty;
            }

            var cookieValue =
                DecryptAndValidateAuthenticationCookie(
                    context.Request.Cookies[FormsAuthenticationCookieName],
                    configuration);

            Guid returnGuid;

            if (string.IsNullOrEmpty(cookieValue) || !Guid.TryParse(cookieValue, out returnGuid))
            {
                return Guid.Empty;
            }

            // Add the auth session id to the context - we need it later to extend the session
            context.Items[AuthSessionIdItemKey] = returnGuid;

            // Translate the AuthSessionId to a User Id
            return configuration.AuthSessionIdStore.Get(returnGuid);
        }

        /// <summary>
        ///     Gets the pre request hook for loading the authenticated user's details
        ///     from the cookie.
        /// </summary>
        /// <param name="configuration">Forms authentication configuration to use</param>
        /// <returns>Pre request hook delegate</returns>
        private static Func<NancyContext, Response> GetLoadAuthenticationHook(
            FormsAuthenticationConfiguration configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            return context =>
                {
                    var userGuid = GetAuthenticatedUserFromCookie(context, configuration);

                    if (userGuid != Guid.Empty)
                    {
                        context.CurrentUser = configuration.UserMapper.GetUserFromIdentifier(userGuid, context);
                    }

                    return null;
                };
        }

        /// <summary>
        ///     Gets the redirect query string key from <see cref="FormsAuthenticationConfiguration" />
        /// </summary>
        /// <param name="configuration">The forms authentication configuration.</param>
        /// <returns>Redirect Querystring key</returns>
        private static string GetRedirectQuerystringKey(FormsAuthenticationConfiguration configuration)
        {
            string redirectQuerystringKey = null;

            if (configuration != null)
            {
                redirectQuerystringKey = configuration.RedirectQuerystringKey;
            }

            if (string.IsNullOrWhiteSpace(redirectQuerystringKey))
            {
                redirectQuerystringKey = FormsAuthenticationConfiguration.DefaultRedirectQuerystringKey;
            }

            return redirectQuerystringKey;
        }

        /// <summary>
        ///     Gets the post request hook for redirecting to the login page
        /// </summary>
        /// <param name="configuration">Forms authentication configuration to use</param>
        /// <returns>Post request hook delegate</returns>
        private static Action<NancyContext> GetRedirectToLoginHook(FormsAuthenticationConfiguration configuration)
        {
            return context =>
                {
                    if (context.Response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        var redirectQuerystringKey = GetRedirectQuerystringKey(configuration);

                        context.Response =
                            context.GetRedirect(
                                $"{configuration.RedirectUrl}?{redirectQuerystringKey}={context.ToFullPath("~" + context.Request.Path + HttpUtility.UrlEncode(context.Request.Url.Query))}");
                    }
                };
        }

        private static Action<NancyContext> GetUpdateSessionCookieHook(FormsAuthenticationConfiguration configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            return context =>
                {
                    var userHasLoggedOut = context.Items.ContainsKey(UserLoggedOutKey);

                    var shouldCopyExistingCookie = context.Request.Cookies.ContainsKey(FormsAuthenticationCookieName)
                                                   && !userHasLoggedOut 
                                                   && context.CurrentUser != null;

                    if (shouldCopyExistingCookie)
                    {
                        var formsAuthCookieValue = context.Request.Cookies[FormsAuthenticationCookieName];

                        var expires = DateTime.UtcNow.AddMinutes(configuration.SlidingSessionExpirationMinutes);

                        var newCookie = new NancyCookie(
                            FormsAuthenticationCookieName,
                            formsAuthCookieValue,
                            true,
                            configuration.RequiresSSL,
                            expires);

                        context.Response.WithCookie(newCookie);

                        // Also update the cache entry to keep consistent
                        configuration.AuthSessionIdStore.Extend((Guid)context.Items[AuthSessionIdItemKey], expires);
                    }
                };
        }
    }
}