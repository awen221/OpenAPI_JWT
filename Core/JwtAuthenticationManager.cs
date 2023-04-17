using System.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace OpenAPI_JWT.Core
{

    /// <summary>
    /// JwtAuthenticationManager
    /// </summary>
    public class JwtAuthenticationManager : JwtAuthenticationManagerInterface
    {

        private TokenConfig _jwtTokenConfig { set; get; }
        private SymmetricSecurityKey symmetricSecurityKey => new(Encoding.ASCII.GetBytes(_jwtTokenConfig.Secret ?? string.Empty));

        private ConcurrentDictionary<string, RefreshToken> _usersRefreshTokens { set; get; }

        /// <summary>
        /// JwtAuthenticationManager
        /// </summary>
        /// <param name="jwtTokenConfig"></param>
        public JwtAuthenticationManager(TokenConfig jwtTokenConfig)
        {
            _jwtTokenConfig = jwtTokenConfig;
            _usersRefreshTokens = new();
        }


        /// <summary>
        /// RemoveExpiredRefreshTokens
        /// </summary>
        /// <param name="now"></param>
        public void RemoveExpiredRefreshTokens(DateTime now)
        {
            var expiredTokens = _usersRefreshTokens.Where(x => x.Value.ExpireAt < now).ToList();

            foreach (var expiredToken in expiredTokens)
            {
                _usersRefreshTokens.TryRemove(expiredToken.Key, out _);
            }
        }
        /// <summary>
        /// RemoveRefreshTokenByUser
        /// </summary>
        /// <param name="user"></param>
        public void RemoveRefreshTokenByUser(string user)
        {
            var refreshTokens = _usersRefreshTokens.Where(x => x.Value.User == user).ToList();
            foreach (var refreshToken in refreshTokens)
            {
                _usersRefreshTokens.TryRemove(refreshToken.Key, out _);
            }
        }


        /// <summary>
        /// GenerateTokens
        /// </summary>
        /// <param name="user"></param>
        /// <param name="claims"></param>
        /// <param name="now"></param>
        /// <returns></returns>
        public (string accessToken, string refreshToken) GenerateTokens(string user, IEnumerable<Claim> claims, DateTime now)
        {

            string GetAccessToken(IEnumerable<Claim> claims, DateTime now)
            {
                var issuer = _jwtTokenConfig.Issuer;
                var audience = _jwtTokenConfig.Audience;
                var expires = now.AddMinutes(_jwtTokenConfig.AccessTokenExpiration);
                var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256Signature);

                var jwtSecurityToken = new JwtSecurityToken(
                    issuer: issuer,
                    audience: audience,
                    claims: claims,
                    expires: expires,
                    signingCredentials: signingCredentials
                    );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

                return tokenString;
            }
            var accessToken = GetAccessToken(claims, now);

            string GetRefreshToken(string user, DateTime now)
            {
                static string GenerateTokenString()
                {
                    var randomNumber = new byte[32];
                    using var randomNumberGenerator = RandomNumberGenerator.Create();
                    randomNumberGenerator.GetBytes(randomNumber);
                    return Convert.ToBase64String(randomNumber);
                }
                var tokenString = GenerateTokenString();
                var expireAt = now.AddMinutes(_jwtTokenConfig.RefreshTokenExpiration);

                var refreshToken = new RefreshToken
                {
                    User = user,
                    ExpireAt = expireAt,
                    TokenString = tokenString,
                };

                void AddOrUpdateRefreshToken(RefreshToken refreshToken)
                {
                    _usersRefreshTokens.AddOrUpdate(refreshToken.TokenString ?? string.Empty, refreshToken, (key, value) => refreshToken);
                }
                AddOrUpdateRefreshToken(refreshToken);

                return tokenString;
            }
            var refreshToken = GetRefreshToken(user, now);

            return (accessToken, refreshToken);
        }

        
        public ClaimsPrincipal RefreshToken_CheckAccessToken(string? accessToken)
        {
            SecurityTokenException SecurityTokenException_InvalidToken = new("InvalidToken");

            if (string.IsNullOrWhiteSpace(accessToken)) throw SecurityTokenException_InvalidToken;

            var claimsPrincipal = new JwtSecurityTokenHandler().ValidateToken(accessToken, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _jwtTokenConfig.Issuer,

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = symmetricSecurityKey,

                ValidAudience = _jwtTokenConfig.Audience,
                ValidateAudience = true,

                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(1)
            }, out var securityToken);

            var jwtSecurityToken = securityToken is null ? null : (JwtSecurityToken)securityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256Signature))
                throw SecurityTokenException_InvalidToken;

            return claimsPrincipal;
        }
        public void RefreshToken_CheckRefreshToken(string refreshToken, string user, DateTime now)
        {
            SecurityTokenException SecurityTokenException_InvalidToken = new("InvalidToken");

            if (!_usersRefreshTokens.TryGetValue(refreshToken, out var existingRefreshToken))
                throw SecurityTokenException_InvalidToken;
            if (existingRefreshToken.User != user || existingRefreshToken.ExpireAt < now)
                throw SecurityTokenException_InvalidToken;
        }

    }

}