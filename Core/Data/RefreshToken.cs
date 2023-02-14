namespace OpenAPI_JWT.Core.Data
{
    /// <summary>
    /// RefreshToken
    /// </summary>
    public class RefreshToken
    {
        /// <summary>
        /// UserName
        /// </summary>
        public string? UserName { get; set; }    // can be used for usage tracking

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
}
