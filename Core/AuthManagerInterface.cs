using System.Security.Claims;
using System.Collections.Immutable;
using System.IdentityModel.Tokens.Jwt;

namespace OpenAPI_JWT.Core
{
    using Data;

    /// <summary>
    /// 
    /// </summary>
    public interface AuthManagerInterface
    {
        /// <summary>
        /// UsersRefreshTokensReadOnlyDictionary
        /// </summary>
        IImmutableDictionary<string, RefreshToken> UsersRefreshTokensReadOnlyDictionary { get; }
        /// <summary>
        /// GenerateTokens
        /// </summary>
        /// <param name="username"></param>
        /// <param name="claims"></param>
        /// <param name="now"></param>
        /// <returns></returns>
        JwtAuthResult GenerateTokens(string username, Claim[] claims, DateTime now);
        /// <summary>
        /// Refresh
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <param name="accessToken"></param>
        /// <param name="now"></param>
        /// <returns></returns>
        JwtAuthResult Refresh(string refreshToken, string accessToken, DateTime now);
        /// <summary>
        /// RemoveExpiredRefreshTokens
        /// </summary>
        /// <param name="now"></param>
        void RemoveExpiredRefreshTokens(DateTime now);
        /// <summary>
        /// RemoveRefreshTokenByUserName
        /// </summary>
        /// <param name="userName"></param>
        void RemoveRefreshTokenByUserName(string userName);
        /// <summary>
        /// DecodeJwtToken
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        (ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token);
    }
}