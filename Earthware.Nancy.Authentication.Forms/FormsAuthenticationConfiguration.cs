namespace Earthware.Nancy.Authentication.Forms
{
    using System;

    using global::Nancy.Cryptography;

    /// <summary>
    ///     Configuration options for forms authentication
    /// </summary>
    public class FormsAuthenticationConfiguration
    {
        internal const string DefaultRedirectQuerystringKey = "returnUrl";

        /// <summary>
        ///     Initializes a new instance of the <see cref="FormsAuthenticationConfiguration" /> class.
        /// </summary>
        public FormsAuthenticationConfiguration()
            : this(CryptographyConfiguration.Default)
        {
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="FormsAuthenticationConfiguration" /> class.
        /// </summary>
        /// <param name="cryptographyConfiguration">Cryptography configuration</param>
        public FormsAuthenticationConfiguration(CryptographyConfiguration cryptographyConfiguration)
        {
            this.CryptographyConfiguration = cryptographyConfiguration;
            this.RedirectQuerystringKey = DefaultRedirectQuerystringKey;
            this.AuthSessionIdStore = new InMemoryAuthSessionIdStore();
        }

        /// <summary>
        ///     Gets or sets the auth session Id store. If not supplied, the InMemoryAuthSessionIdStore is used.
        /// </summary>
        public IAuthSessionIdStore AuthSessionIdStore { get; set; }

        /// <summary>
        ///     Gets or sets the cryptography configuration
        /// </summary>
        public CryptographyConfiguration CryptographyConfiguration { get; set; }

        /// <summary>
        ///     Gets or sets whether to redirect to login page during unauthorized access.
        /// </summary>
        public bool DisableRedirect { get; set; }

        /// <summary>
        ///     Gets or sets the domain of the auth cookie
        /// </summary>
        public string Domain { get; set; }

        /// <summary>
        ///     Ensures that the values provided to the Configuration are valid.
        /// </summary>
        /// <exception cref="Exception"></exception>
        public void Validate()
        {
            if (!this.DisableRedirect && string.IsNullOrEmpty(this.RedirectUrl))
            {
                throw new ArgumentException("If DisableRedirect is False, you must provide a value for RedirectUrl", nameof(this.RedirectUrl));
            }

            if (this.UserMapper == null)
            {
                throw new ArgumentException("You must provide a UserMapper", nameof(this.UserMapper));
            }

            if (this.AuthSessionIdStore == null)
            {
                throw new ArgumentException("You must provide an AuthSessionIdStore. If you do not explicitly set this property, the InMemoryAuthSessionIdStore will be used.", nameof(this.AuthSessionIdStore));
            }

            if (this.CryptographyConfiguration == null)
            {
                throw new ArgumentException("You must provide a CryptograpyConfiguration", nameof(this.CryptographyConfiguration));
            }

            if (this.CryptographyConfiguration.EncryptionProvider == null)
            {
                throw new ArgumentException("The supplied CryptographyConfiguration does not contain an EncryptionProvider", nameof(this.CryptographyConfiguration.EncryptionProvider));
            }

            if (this.CryptographyConfiguration.HmacProvider == null)
            {
                throw new ArgumentException("The supplied CryptographyConfiguration does not contain an HmacProvider", nameof(this.CryptographyConfiguration.HmacProvider));
            }

            if (this.SlidingSessionExpirationMinutes <= 0)
            {
                throw new ArgumentException("The SlidingSessionExpirationMinutes value must be greater than 0", nameof(this.SlidingSessionExpirationMinutes));
            }

            if (string.IsNullOrEmpty(this.LogoutPath))
            {
                throw new ArgumentException("You must provide the path to your Logout endpoint in the LogoutPath property.", nameof(this.LogoutPath));
            }
        }

        /// <summary>
        ///     Gets or sets the path of the logout endpoint. Needed for sliding expiration.
        /// </summary>
        public string LogoutPath { get; set; } = "/logout";

        /// <summary>
        ///     Gets or sets the path of the auth cookie
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        ///     Gets or sets the forms authentication query string key for storing the return url
        /// </summary>
        public string RedirectQuerystringKey { get; set; }

        /// <summary>
        ///     Gets or sets the redirect url for pages that require authentication
        /// </summary>
        public string RedirectUrl { get; set; }

        /// <summary>
        ///     Gets or sets RequiresSSL property
        /// </summary>
        /// <value>The flag that indicates whether SSL is required</value>
        public bool RequiresSSL { get; set; }

        /// <summary>
        ///     Gets or sets the duration of the user's session
        /// </summary>
        public int SlidingSessionExpirationMinutes { get; set; } = 30;

        /// <summary>
        ///     Gets or sets the username/identifier mapper
        /// </summary>
        public IUserMapper UserMapper { get; set; }
    }
}