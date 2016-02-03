namespace Earthware.Nancy.Authentication.Forms
{
    using System;

    public interface IAuthSessionIdStore
    {
        Guid Add(Guid persistentUserIdentifier, DateTime expiryTimeUtc);

        Guid Get(Guid authSessionIdentifier);

        void Extend(Guid authSessionIdentifier, DateTime expiryTimeUtc);

        void Remove(Guid authSessionIdentifier);
    }
}