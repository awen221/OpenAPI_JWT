using System.Security.Claims;

namespace OpenAPI_JWT.Core
{

    /// <summary>
    /// JwtAuthenticationManagerInterface
    /// </summary>
    public interface JwtAuthenticationManagerInterface
    {

        /// <summary>
        /// RemoveExpiredRefreshTokens
        /// </summary>
        /// <param name="now"></param>
        void RemoveExpiredRefreshTokens(DateTime now);
        /// <summary>
        /// RemoveRefreshTokenByUser
        /// </summary>
        /// <param name="user"></param>
        void RemoveRefreshTokenByUser(string user);

        /// <summary>
        /// GenerateTokens
        /// </summary>
        /// <param name="user"></param>
        /// <param name="claims"></param>
        /// <param name="now"></param>
        /// <returns></returns>
        (string accessToken, string refreshToken) GenerateTokens(string user, IEnumerable<Claim> claims, DateTime now);


        ClaimsPrincipal RefreshToken_CheckAccessToken(string? accessToken);
        void RefreshToken_CheckRefreshToken(string refreshToken, string user, DateTime now);

    }

    /// <summary>
    /// RefreshToken
    /// </summary>
    class RefreshToken
    {
        // can be used for usage tracking
        /// <summary>
        /// User
        /// </summary>
        public string? User { get; set; }

        // can optionally include other metadata, such as user agent, ip address, device name, and so on
        /// <summary>
        /// TokenString
        /// </summary>
        public string? TokenString { get; set; }

        /// <summary>
        /// ExpireAt
        /// </summary>
        public DateTime ExpireAt { get; set; }
    }

    /// <summary>
    /// TokenConfig
    /// </summary>
    public class TokenConfig
    {
        /// <summary>
        /// Secret
        /// </summary>
        public string? Secret { get; set; }

        /// <summary>
        /// Issuer
        /// </summary>
        public string? Issuer { get; set; }

        /// <summary>
        /// Audience
        /// </summary>
        public string? Audience { get; set; }

        /// <summary>
        /// AccessTokenExpiration
        /// </summary>
        public int AccessTokenExpiration { get; set; }

        /// <summary>
        /// RefreshTokenExpiration
        /// </summary>
        public int RefreshTokenExpiration { get; set; }
    }

}