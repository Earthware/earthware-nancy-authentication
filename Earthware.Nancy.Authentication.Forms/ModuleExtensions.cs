namespace Earthware.Nancy.Authentication.Forms
{
    using System;

    using global::Nancy;
    using global::Nancy.Extensions;

    /// <summary>
    /// Module extensions for login/logout of forms auth
    /// </summary>
    public static class ModuleExtensions
    {
        /// <summary>
        /// Logs the user in and returns either an empty 200 response for ajax requests, or a redirect response for non-ajax. <seealso cref="RequestExtensions.IsAjaxRequest"/>
        /// </summary>
        /// <param name="module">Nancy module</param>
        /// <param name="userIdentifier">User identifier guid</param>
        /// <param name="cookieExpiry">Optional expiry date for the cookie (for 'Remember me')</param>
        /// <param name="fallbackRedirectUrl">Url to redirect to if none in the querystring</param>
        /// <returns>Nancy response with redirect if request was not ajax, otherwise with OK.</returns>
        public static Response Login(this INancyModule module, Guid userIdentifier, DateTime? cookieExpiry = null, string fallbackRedirectUrl = "/")
        {
            return module.Context.Request.IsAjaxRequest() ?
                LoginWithoutRedirect(module, userIdentifier, cookieExpiry) :
                LoginAndRedirect(module, userIdentifier, cookieExpiry, fallbackRedirectUrl);
        }

        /// <summary>
        /// Logs the user in with the given user guid and redirects.
        /// </summary>
        /// <param name="module">Nancy module</param>
        /// <param name="userIdentifier">User identifier guid</param>
        /// <param name="cookieExpiry">Optional expiry date for the cookie (for 'Remember me')</param>
        /// <param name="fallbackRedirectUrl">Url to redirect to if none in the querystring</param>
        /// <returns>Nancy response instance</returns>
        public static Response LoginAndRedirect(this INancyModule module, Guid userIdentifier, DateTime? cookieExpiry = null, string fallbackRedirectUrl = "/")
        {
            return EarthwareFormsAuthentication.UserLoggedInRedirectResponse(module.Context, userIdentifier, cookieExpiry, fallbackRedirectUrl);
        }

        /// <summary>
        /// Logs the user in with the given user guid and returns ok response.
        /// </summary>
        /// <param name="module">Nancy module</param>
        /// <param name="userIdentifier">User identifier guid</param>
        /// <param name="cookieExpiry">Optional expiry date for the cookie (for 'Remember me')</param>
        /// <returns>Nancy response instance</returns>
        public static Response LoginWithoutRedirect(this INancyModule module, Guid userIdentifier, DateTime? cookieExpiry = null)
        {
            return EarthwareFormsAuthentication.UserLoggedInResponse(userIdentifier, cookieExpiry);
        }

        /// <summary>
        /// Logs the user out and returns either an empty 200 response for ajax requests, or a redirect response for non-ajax. <seealso cref="RequestExtensions.IsAjaxRequest"/>
        /// </summary>
        /// <param name="module">Nancy module</param>
        /// <param name="redirectUrl">URL to redirect to</param>
        /// <returns>Nancy response with redirect if request was not ajax, otherwise with OK.</returns>
        public static Response Logout(this INancyModule module, string redirectUrl)
        {
            return module.Context.Request.IsAjaxRequest() ?
               EarthwareFormsAuthentication.LogOutResponse(module.Context) :
               EarthwareFormsAuthentication.LogOutAndRedirectResponse(module.Context, redirectUrl);
        }

        /// <summary>
        /// Logs the user out and redirects
        /// </summary>
        /// <param name="module">Nancy module</param>
        /// <param name="redirectUrl">URL to redirect to</param>
        /// <returns>Nancy response instance</returns>
        public static Response LogoutAndRedirect(this INancyModule module, string redirectUrl)
        {
            return EarthwareFormsAuthentication.LogOutAndRedirectResponse(module.Context, redirectUrl);
        }

        /// <summary>
        /// Logs the user out without a redirect
        /// </summary>
        /// <param name="module">Nancy module</param>
        /// <returns>Nancy response instance</returns>
        public static Response LogoutWithoutRedirect(this INancyModule module)
        {
            return EarthwareFormsAuthentication.LogOutResponse(module.Context);
        }
    }
}