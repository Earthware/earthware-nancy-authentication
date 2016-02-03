namespace Earthware.Nancy.Authentication.Forms.Raven
{
    using System;

    public class AuthSessionCacheEntry
    {
        public AuthSessionCacheEntry()
        {
            this.Id = Guid.NewGuid();
        }

        public Guid Id { get; set; }

        public Guid UserId { get; set; }

        public DateTime ExpiryTimeUtc { get; set; }

        public bool IsValid()
        {
            return this.ExpiryTimeUtc > DateTime.UtcNow;
        }
    }
}