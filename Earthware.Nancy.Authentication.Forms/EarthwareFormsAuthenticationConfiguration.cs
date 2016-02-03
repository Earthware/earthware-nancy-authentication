namespace Earthware.Nancy.Authentication.Forms
{
    public class EarthwareFormsAuthenticationConfiguration : global::Nancy.Authentication.Forms.FormsAuthenticationConfiguration
    {
        public EarthwareFormsAuthenticationConfiguration()
        {
            this.AuthSessionIdStore = new InMemoryAuthSessionIdStore();
        }

        public override bool IsValid =>
                base.IsValid && this.AuthSessionIdStore != null
                && (!SlidingSessionExpirationMinutes.HasValue
                    || (SlidingSessionExpirationMinutes.HasValue && !string.IsNullOrEmpty(this.LogoutPath)));

        public IAuthSessionIdStore AuthSessionIdStore { get; set; }

        public int? SlidingSessionExpirationMinutes { get; set; }

        public string LogoutPath { get; set; }
    }
}