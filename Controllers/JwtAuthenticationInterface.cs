using Microsoft.AspNetCore.Mvc;

namespace OpenAPI_JWT.Controllers
{
    /// <summary>
    /// JwtAuthenticationInterface
    /// </summary>
    public interface JwtAuthenticationInterface
    {
        /// <summary>
        /// Login
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        IActionResult Login(string user, string password);
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

        ///// <summary>
        ///// GetCurrentUser
        ///// </summary>
        ///// <returns></returns>
        //IActionResult GetCurrentUser();
    }
}