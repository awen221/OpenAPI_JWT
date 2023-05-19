1.  建立專案"空的ASP.NET Core"  
架構：NET6.0  
（　）針對HTTPS進行設定  
（　）啟用Docker  
（　）Do not use top-level statements

1. 已設定在SwaggerUI頁面上輸出函式註解，需做以下設定否則會執行異常：  
專案屬性->建置->輸出->文件檔案  
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
    new Open_API_JWT.StartUp().Main(args);

    namespace Open_API_JWT
    {
        using Microsoft.OpenApi.Models;
        using Controllers;

        /// <inheritdoc/>
        public class StartUp : OpenAPI_JWT.StartUp
        {
            /// <inheritdoc/>
            protected override Dictionary<string, OpenApiInfo> GetSwaggerDocs()
            {
                var dict = new Dictionary<string, OpenApiInfo>()
                {
                    {
                        "Open_API_JWT",
                        new OpenApiInfo(){
                            Title="Open_API_JWT",
                            Version="1.0.0.0"
                        }
                    }
                };

                return dict;
            }

            /// <inheritdoc/>
            protected override void WebApplicationBuilder_Process(WebApplicationBuilder builder) =>
                base.WebApplicationBuilder_Process(builder);

            /// <inheritdoc/>
            protected override void WebApplication_Process(WebApplication app) =>
                base.WebApplication_Process(app);
        }
    }

    ```
1. Controller範例：
    ```
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Authorization;

    using OpenAPI_JWT.Core;

    namespace OpenAPI_JWT.Template.Controllers
    {

        /// <summary>
        /// AuthenticationController
        /// </summary>
        [Route("[controller]/[action]")][ApiController]
        public class Authentication : OpenAPI_JWT.Controllers.Authentication
        {

            /// <summary>
            /// AuthenticationController
            /// </summary>
            /// <param name="jwtAuthManager"></param>
            public Authentication(AuthManagerInterface jwtAuthManager) : base(jwtAuthManager) { }

            /// <summary>
            /// 登入
            /// </summary>
            /// <param name="UserName"></param>
            /// <param name="Password"></param>
            /// <returns></returns>
            [HttpPost][AllowAnonymous]
            public override IActionResult Login(string UserName, string Password) => base.Login(UserName, Password);

            /// <summary>
            /// 更新憑證
            /// </summary>
            /// <param name="request"></param>
            /// <returns></returns>
            [HttpPost][Authorize]
            public override async Task<IActionResult> RefreshToken([FromBody]string request) => await base.RefreshToken(request);

            /// <summary>
            /// 取得當前使用者
            /// </summary>
            /// <returns></returns>
            [HttpGet][Authorize]
            public override IActionResult GetCurrentUser() => base.GetCurrentUser();

            /// <summary>
            /// 登出
            /// </summary>
            /// <returns></returns>
            [HttpPost][Authorize]
            public override IActionResult Logout() => base.Logout();

        }

    }
    ```