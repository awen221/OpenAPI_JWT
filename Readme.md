1.  建立"空的ASP.NET Core"專案
<br>
架構：NET6.0
<br>
（　）針對HTTPS進行設定
<br>
（　）啟用Docker
<br>
<br>
（Ｖ）Do not use top-level statements

1. 已設定在SwaggerUI頁面上輸出函式註解，需做以下設定否則會執行異常：
<br>
專案屬性->建置->輸出->文件檔案
<br>
（Ｖ）產生包含API文件的檔案。

1. 需在 appsettings.json 加入 jwtTokenConfig 如下：
    ```
    "jwtTokenConfig": {
        "secret": "1234567890123456789",
        "issuer": "https://mywebapi.com",
        "audience": "https://mywebapi.com",
        "accessTokenExpiration": 20,
        "refreshTokenExpiration": 60
    }
    ```
1. 加入OpenAPI_JWT的專案參考

1. 覆寫Program如下：
    ```
    /// <summary>
    /// Program
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Main
        /// </summary>
        /// <param name="args"></param>
        public static void Main(string[] args) => new StartUp().Main(args);
    }

    /// <summary>
    /// StartUp
    /// </summary>
    public class StartUp : global::OpenAPI_JWT.StartUp
    {
        /// <summary>
        /// 
        /// </summary>
        protected override string Title => throw new NotImplementedException();
        /// <summary>
        /// 
        /// </summary>
        protected override Version Version => throw new NotImplementedException();
        /// <summary>
        /// 
        /// </summary>
        protected override string Description => throw new NotImplementedException();

        /// <summary>
        /// WebApplicationBuilder_Process
        /// </summary>
        /// <param name="builder"></param>
        protected override void WebApplicationBuilder_Process(WebApplicationBuilder builder)
        {
            base.WebApplicationBuilder_Process(builder);
        }
        /// <summary>
        /// WebApplication_Process
        /// </summary>
        /// <param name="app"></param>
        protected override void WebApplication_Process(WebApplication app)
        {
            base.WebApplication_Process(app);
        }
    }
    ```
1. Controller範例：
    ```
    using OpenAPI_JWT.Core;

    /// <summary>
    /// Authentication
    /// </summary>
    public class Authentication : Controller, Authentication_Interface
    {
        private readonly AuthManagerInterface _jwtAuthManager;
        /// <summary>
        /// AuthenticationController
        /// </summary>
        /// <param name="jwtAuthManager"></param>
        public Authentication(AuthManagerInterface jwtAuthManager)
        {
            _jwtAuthManager = jwtAuthManager;
        }


        /// <summary>
        /// CheckPasswordEmpty
        /// 設定是否檢查空白的密碼為錯誤，有的系統允許使用空白的密碼
        /// </summary>
        virtual protected bool CheckPasswordEmpty => false;
        /// <summary>
        /// GetRole
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        virtual protected string GetRole(string userName) => "User";
        /// <summary>
        /// 處理Authentication邏輯，可由子類別覆寫
        /// </summary>
        /// <param name="UserName"></param>
        /// <param name="Password"></param>
        /// <returns></returns>
        virtual protected User AuthenticationCheck(string UserName, string Password)
        {
            if (UserName is "UserName" && Password is "Password")
            {
                return new User()
                {
                    UserName = "UserName",
                    OriginalUserName = "OriginalUserName",
                    Role = "Role",
                };
            }

            throw new Exception("AuthenticationCheck Fail");
        }
        /// <summary>
        /// Process_AuthenticationCheckResult
        /// </summary>
        /// <param name="result"></param>
        /// <param name="UserName"></param>
        /// <param name="Password"></param>
        /// <returns></returns>
        virtual protected IActionResult Process_AuthenticationCheckResultAsync(User result, string UserName, string Password)
        {
            var data = result;

            var Role = GetRole(data.UserName);
            var OriginalUserNameUrlEncode = HttpUtility.UrlEncode(data.OriginalUserName);
            var claims = new[]
            {
                new Claim(ClaimTypes.Name,data.UserName),
                new Claim(ClaimTypes.Role, Role),

                new Claim(nameof(OriginalUserNameUrlEncode),OriginalUserNameUrlEncode),
            };

            var jwtResult = _jwtAuthManager.GenerateTokens(data.UserName, claims, DateTime.Now);

            return Ok(new {
                UserName = data.UserName,
                OriginalUserName = data.OriginalUserName,
                Role = Role,

                AccessToken = jwtResult.AccessToken,
                RefreshToken = jwtResult.RefreshToken?.TokenString ?? string.Empty,
            });
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        virtual protected User GetUser()
        {
            var user = new User();

            user.UserName = User.Identity?.Name ?? string.Empty;
            string OriginalUserNameUrlEncode = User.FindFirst(nameof(OriginalUserNameUrlEncode))?.Value ?? string.Empty;
            user.OriginalUserName = HttpUtility.UrlDecode(OriginalUserNameUrlEncode);
            user.Role = User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty;

            return user;
        }


        #region 介面實做

        /// <summary>
        /// Login
        /// </summary>
        /// <param name="UserName"></param>
        /// <param name="Password"></param>
        /// <returns></returns>
        virtual public IActionResult Login(string UserName, string Password)
        {
            try
            {
                bool check_para_is_empty(string? para)
                {
                    if (!string.IsNullOrEmpty(para))
                        if (para.Trim() != string.Empty)
                            return false;

                    return true;
                }
                if (check_para_is_empty(UserName))
                {
                    throw new Exception("user is empty");
                }
                if (CheckPasswordEmpty)
                {
                    if (check_para_is_empty(Password))
                    {
                        throw new Exception("password is empty");
                    }
                }

                var result = AuthenticationCheck(UserName, Password);
                if (result is null) throw new Exception("result is null");

                return Process_AuthenticationCheckResultAsync(result, UserName, Password);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        virtual public IActionResult GetCurrentUser()
        {
            try
            {
                var user = GetUser();

                return Ok(new User()
                {
                    UserName = user.UserName,
                    OriginalUserName = user.OriginalUserName,
                    Role = user.Role,
                });
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

                var accessToken = await HttpContext.GetTokenAsync("Bearer", "access_token");

                var jwtResult = _jwtAuthManager.Refresh(refreshToken, accessToken ?? string.Empty, DateTime.Now);

                var user = GetUser();

                return Ok(new {
                    UserName = user.UserName,
                    OriginalUserName = user.OriginalUserName,
                    Role = user.Role,
                    AccessToken = jwtResult.AccessToken ?? string.Empty,
                    RefreshToken = jwtResult.RefreshToken?.TokenString ?? string.Empty,
                });
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
                var userName = User.Identity?.Name;
                if (userName is not null)
                {
                    _jwtAuthManager.RemoveRefreshTokenByUserName(userName);
                }
                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        #endregion
    }
    ```