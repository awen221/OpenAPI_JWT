using System.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Collections.Immutable;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace OpenAPI_JWT.Core
{
    using Data;

    /// <summary>
    /// 
    /// </summary>
    public class AuthManager : AuthManagerInterface
    {
        private readonly ConcurrentDictionary<string, RefreshToken> _usersRefreshTokens;  // can store in a database or a distributed cache
        private readonly TokenConfig _jwtTokenConfig;
        private readonly byte[] _secret;
        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtTokenConfig"></param>
        public AuthManager(TokenConfig jwtTokenConfig)
        {
            _jwtTokenConfig = jwtTokenConfig;
            _usersRefreshTokens = new ConcurrentDictionary<string, RefreshToken>();
            _secret = Encoding.ASCII.GetBytes(jwtTokenConfig.Secret ?? string.Empty);
        }

        /// <summary>
        /// UsersRefreshTokensReadOnlyDictionary
        /// </summary>
        public IImmutableDictionary<string, RefreshToken> UsersRefreshTokensReadOnlyDictionary => _usersRefreshTokens.ToImmutableDictionary();
        /// <summary>
        /// GenerateTokens
        /// </summary>
        /// <param name="username"></param>
        /// <param name="claims"></param>
        /// <param name="now"></param>
        /// <returns></returns>
        public JwtAuthResult GenerateTokens(string username, Claim[] claims, DateTime now)
        {
            var shouldAddAudienceClaim = string.IsNullOrWhiteSpace(claims?.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Aud)?.Value);
            var jwtToken = new JwtSecurityToken(
                _jwtTokenConfig.Issuer,
                shouldAddAudienceClaim ? _jwtTokenConfig.Audience : string.Empty,
                claims,
                expires: now.AddMinutes(_jwtTokenConfig.AccessTokenExpiration),
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(_secret), SecurityAlgorithms.HmacSha256Signature));

            var accessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            static string GenerateRefreshTokenString()
            {
                var randomNumber = new byte[32];
                using var randomNumberGenerator = RandomNumberGenerator.Create();
                randomNumberGenerator.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
            var refreshToken = new RefreshToken
            {
                UserName = username,
                TokenString = GenerateRefreshTokenString(),
                ExpireAt = now.AddMinutes(_jwtTokenConfig.RefreshTokenExpiration)
            };
            _usersRefreshTokens.AddOrUpdate(refreshToken.TokenString, refreshToken, (_, _) => refreshToken);

            return new JwtAuthResult
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }
        /// <summary>
        /// Refresh
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <param name="accessToken"></param>
        /// <param name="now"></param>
        /// <returns></returns>
        /// <exception cref="SecurityTokenException"></exception>
        public JwtAuthResult Refresh(string refreshToken, string accessToken, DateTime now)
        {
            var (principal, jwtToken) = DecodeJwtToken(accessToken);
            if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256Signature))
            {
                throw new SecurityTokenException("Invalid token");
            }

            var userName = principal.Identity?.Name ?? string.Empty;
            if (!_usersRefreshTokens.TryGetValue(refreshToken, out var existingRefreshToken))
            {
                throw new SecurityTokenException("Invalid token");
            }
            if (existingRefreshToken.UserName != userName || existingRefreshToken.ExpireAt < now)
            {
                throw new SecurityTokenException("Invalid token");
            }

            return GenerateTokens(userName, principal.Claims.ToArray(), now); // need to recover the original claims
        }
        // optional: clean up expired refresh tokens
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
        // can be more specific to ip, user agent, device name, etc.
        /// <summary>
        /// RemoveRefreshTokenByUserName
        /// </summary>
        /// <param name="userName"></param>
        public void RemoveRefreshTokenByUserName(string userName)
        {
            var refreshTokens = _usersRefreshTokens.Where(x => x.Value.UserName == userName).ToList();
            foreach (var refreshToken in refreshTokens)
            {
                _usersRefreshTokens.TryRemove(refreshToken.Key, out _);
            }
        }
        /// <summary>
        /// DecodeJwtToken
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="SecurityTokenException"></exception>
        public (ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new SecurityTokenException("Invalid token");
            }
            var principal = new JwtSecurityTokenHandler()
                .ValidateToken(token,
                    new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = _jwtTokenConfig.Issuer,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(_secret),
                        ValidAudience = _jwtTokenConfig.Audience,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromMinutes(1)
                    },
                    out var validatedToken);

            return (principal, (JwtSecurityToken)validatedToken);
        }
    }
}