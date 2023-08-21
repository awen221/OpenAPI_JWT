using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace OpenAPI_JWT.Controllers
{
    using Core;
    using LoginPara = JwtAuthenticationInterface.LoginPara;

    /// <summary>
    /// JwtAuthentication 
    /// </summary>
    public class JwtAuthentication : Controller, JwtAuthenticationInterface
    {

        private JwtAuthenticationManagerInterface jwtAuthManager { set; get; }

        /// <summary>
        /// ClaimsPrincipal_User
        /// </summary>
        protected string ClaimsPrincipal_User => User.FindFirst(Claims.user)?.Value ?? string.Empty;

        /// <summary>
        /// GetJwtActionResult
        /// </summary>
        /// <param name="user"></param>
        /// <param name="claims"></param>
        /// <param name="now"></param>
        /// <returns></returns>
        virtual protected IActionResult GetJwtActionResult(string user, IEnumerable<Claim> claims, DateTime now)
        {
            var (accessToken, refreshToken) = jwtAuthManager.GenerateTokens(user, claims, now);
            return Ok(new
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
            });
        }

        /// <summary>
        /// CheckPasswordEmpty
        /// 設定是否檢查空白的密碼為錯誤，有的系統允許使用空白的密碼
        /// </summary>
        virtual protected bool CheckPasswordEmpty => false;

        /// <summary>
        /// 取得認證，可由子類別覆寫
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        virtual protected void GetAuthentication(string user, string password) { }

        /// <summary>
        /// 取得授權，可由子類別覆寫
        /// </summary>
        /// <param name="claims"></param>
        /// <returns></returns>
        virtual protected IEnumerable<Claim> GetAuthorization(string user, IEnumerable<Claim> claims) => claims;

        /// <summary>
        /// JwtAuthentication 
        /// </summary>
        /// <param name="_jwtAuthManager"></param>
        public JwtAuthentication(JwtAuthenticationManagerInterface _jwtAuthManager)
        {
            this.jwtAuthManager = _jwtAuthManager;
        }

        /// <summary>
        /// Login
        /// </summary>
        /// <param name="loginPara"></param>
        /// <returns></returns>
        virtual public IActionResult Login([FromBody] LoginPara loginPara)
        {
            try
            {
                var user = loginPara.user;
                var password=loginPara.password;

                static bool check_para_is_empty(string? para)
                {
                    if (!string.IsNullOrEmpty(para))
                        if (para.Trim() != string.Empty)
                            return false;

                    return true;
                }
                if (check_para_is_empty(user))
                    throw new Exception("user is empty");

                if (CheckPasswordEmpty)
                    if (check_para_is_empty(password))
                        throw new Exception("password is empty");

                GetAuthentication(user, password);

                IEnumerable<Claim> claims;

                static IEnumerable<Claim> GenerateClaims(string user)
                    => new List<Claim> { new Claim(Claims.user, user), };
                claims = GenerateClaims(user);

                claims = GetAuthorization(user,claims);

                var now = DateTime.Now;
                return GetJwtActionResult(user, claims, now);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        /// <summary>
        /// RefreshToken
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        virtual public async Task<IActionResult> RefreshToken(string refreshToken)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(refreshToken)) return Unauthorized();
                var user = ClaimsPrincipal_User;
                var now = DateTime.Now;
                jwtAuthManager.RefreshToken_CheckRefreshToken(refreshToken, user, now);

                var accessToken = await HttpContext.GetTokenAsync("Bearer", "access_token");
                var claims = jwtAuthManager.RefreshToken_CheckAccessToken(accessToken).Claims;

                return GetJwtActionResult(user, claims, now);
            }
            catch (SecurityTokenException e)
            {
                return Unauthorized(e.Message); // return 401 so that the client side can redirect the user to login page
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        /// <summary>
        /// Logout
        /// </summary>
        /// <returns></returns>
        virtual public IActionResult Logout()
        {
            try
            {
                var user = ClaimsPrincipal_User;
                if (user is not null)
                {
                    jwtAuthManager.RemoveRefreshTokenByUser(user);
                }
                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

    }
}