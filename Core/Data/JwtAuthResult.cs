namespace OpenAPI_JWT.Core.Data
{
    /// <summary>
    /// JwtAuthResult
    /// </summary>
    public class JwtAuthResult
    {
        /// <summary>
        /// AccessToken
        /// </summary>
        public string? AccessToken { get; set; }

        /// <summary>
        /// RefreshToken
        /// </summary>
        public RefreshToken? RefreshToken { get; set; }
    }
}
