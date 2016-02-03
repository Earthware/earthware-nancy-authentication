namespace Earthware.Nancy.Authentication.Forms
{
    using System;
    using System.Collections.Concurrent;

    public class InMemoryAuthSessionIdStore : IAuthSessionIdStore
    {
        private static ConcurrentDictionary<Guid, CacheEntry> cache = new ConcurrentDictionary<Guid, CacheEntry>();

        public Guid Add(Guid persistentUserIdentifier, DateTime expiryTimeUtc)
        {
            var key = Guid.NewGuid();

            var newEntry = new CacheEntry
            {
                ExpiryTime = expiryTimeUtc,
                PersistentUserIdentifier = persistentUserIdentifier
            };

            cache[key] = newEntry;

            return key;
        }

        public void Extend(Guid authSessionIdentifier, DateTime expiryTimeUtc)
        {
            var item = cache[authSessionIdentifier];
            item.ExpiryTime = expiryTimeUtc;
        }

        public void Remove(Guid authSessionIdentifier)
        {
            CacheEntry result;
            cache.TryRemove(authSessionIdentifier, out result);
        }

        public Guid Get(Guid authSessionIdentifier)
        {
            CacheEntry item;
            if (cache.TryGetValue(authSessionIdentifier, out item))
            {
                if (item.IsValid())
                {
                    return item.PersistentUserIdentifier;
                }

                this.Remove(authSessionIdentifier);
            }

            return Guid.Empty;
        }

        private class CacheEntry
        {
            public DateTime ExpiryTime { get; set; }

            public Guid PersistentUserIdentifier { get; set; }

            public bool IsValid()
            {
                return ExpiryTime > DateTime.UtcNow;
            }
        }
    }
}