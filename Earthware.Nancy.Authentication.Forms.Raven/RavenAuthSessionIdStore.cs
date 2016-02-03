namespace Earthware.Nancy.Authentication.Forms.Raven
{
    using System;

    using global::Raven.Client;

    public class RavenAuthSessionIdStore : IAuthSessionIdStore
    {
        private readonly IDocumentSession session;

        public RavenAuthSessionIdStore(IDocumentSession session)
        {
            this.session = session;
        }

        public Guid Add(Guid persistentUserIdentifier, DateTime expiryTimeUtc)
        {
            var doc = new AuthSessionCacheEntry { UserId = persistentUserIdentifier, ExpiryTimeUtc = expiryTimeUtc };
            this.session.Store(doc);

            return doc.Id;
        }

        public Guid Get(Guid authSessionIdentifier)
        {
            var doc = this.session.Load<AuthSessionCacheEntry>(authSessionIdentifier);

            if (doc == null)
            {
                return Guid.Empty;
            }

            if (doc.IsValid())
            {
                return doc.UserId;
            }

            this.session.Delete(doc);
            return Guid.Empty;
        }

        public void Extend(Guid authSessionIdentifier, DateTime expiryTimeUtc)
        {
            var doc = this.session.Load<AuthSessionCacheEntry>(authSessionIdentifier);

            if (doc != null)
            {
                doc.ExpiryTimeUtc = expiryTimeUtc;
            }
        }

        public void Remove(Guid authSessionIdentifier)
        {
            var doc = this.session.Load<AuthSessionCacheEntry>(authSessionIdentifier);

            if (doc != null)
            {
                this.session.Delete(doc);
            }
        }
    }
}