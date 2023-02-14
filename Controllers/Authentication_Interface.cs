using Microsoft.AspNetCore.Mvc;

namespace OpenAPI_JWT.Controllers
{
    /// <summary>
    /// Authentication_Interface
    /// </summary>
    public interface Authentication_Interface
    {
        /// <summary>
        /// Login
        /// </summary>
        /// <param name="UserName"></param>
        /// <param name="Password"></param>
        /// <returns></returns>
        IActionResult Login(string UserName, string Password);
        /// <summary>
        /// GetCurrentUser
        /// </summary>
        /// <returns></returns>
        IActionResult GetCurrentUser();
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