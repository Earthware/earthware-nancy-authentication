namespace Earthware.Nancy.Authentication.Forms
{
    using System;

    using global::Nancy;
    using global::Nancy.Authentication.Forms;
    using global::Nancy.Security;

    /// <summary>
    /// AuthSessionId aware wrapper for the user's implementation of IUserMapper. Internally ensures that when
    /// the FormsAuthentication code tries to retrieve a user by AuthSessionId, the Id is mapped to the user's
    /// real Id before being passed to the original implementation.
    /// </summary>
    public class AuthSessionIdUserMapper : IUserMapper
    {
        private readonly IUserMapper baseMapper;

        private readonly IAuthSessionIdStore sessionIdStore;

        /// <summary>
        /// Creates a new instance of AuthSessionIdUserMapper.
        /// </summary>
        /// <param name="baseMapper">The standard user mapper that knows how to retrieve users by their default Id.</param>
        /// <param name="sessionIdStore">An implementation of IAuthSessionIdStore that will be used to map AuthSessionIds to User Ids</param>
        public AuthSessionIdUserMapper(IUserMapper baseMapper, IAuthSessionIdStore sessionIdStore)
        {
            this.baseMapper = baseMapper;
            this.sessionIdStore = sessionIdStore;
        }

        /// <summary>
        /// Retrieve the user with the given AuthSessionId.
        /// </summary>
        /// <param name="identifier">The AuthSessionId for the user.</param>
        /// <param name="context">The NancyContext for the current request.</param>
        /// <returns>The matching user identity, or null if there is no match.</returns>
        public IUserIdentity GetUserFromIdentifier(Guid identifier, NancyContext context)
        {
            var id = this.sessionIdStore.Get(identifier);

            return this.baseMapper.GetUserFromIdentifier(id, context);
        }
    }
}