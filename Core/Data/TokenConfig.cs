namespace OpenAPI_JWT.Core.Data
{
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