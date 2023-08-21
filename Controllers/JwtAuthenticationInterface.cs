using Microsoft.AspNetCore.Mvc;

namespace OpenAPI_JWT.Controllers
{
    /// <summary>
    /// JwtAuthenticationInterface
    /// </summary>
    public interface JwtAuthenticationInterface
    {
        /// <summary>
        /// LoginPara
        /// </summary>
        public struct LoginPara
        {
            public string user { set; get; }
            public string password { set; get; }
        }
        /// <summary>
        /// Login
        /// </summary>
        /// <param name="loginPara"></param>
        /// <returns></returns>
        IActionResult Login(LoginPara loginPara);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="RefreshToken"></param>
        /// <returns></returns>
        Task<IActionResult> RefreshToken(string RefreshToken);
        /// <summary>
        /// Logout
        /// </summary>
        /// <returns></returns>
        IActionResult Logout();
    }
}