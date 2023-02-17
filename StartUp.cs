using System.Text;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;

using OpenAPI_JWT.Core;
using OpenAPI_JWT.Core.Data;

namespace OpenAPI_JWT
{
    /// <summary>
    /// StartUp
    /// </summary>
    abstract public class StartUp : OpenAPI.StartUp
    {

        /// <summary>
        /// WebApplicationBuilder_Process
        /// </summary>
        /// <param name="builder"></param>
        protected override void WebApplicationBuilder_Process(WebApplicationBuilder builder)
        {
            base.WebApplicationBuilder_Process(builder);

            #region ConfigureKestrel作用待確認
            //builder.WebHost.ConfigureKestrel(serverOptions =>
            //{
            //    serverOptions.Limits.MinRequestBodyDataRate = new MinDataRate(100, TimeSpan.FromSeconds(10));
            //    serverOptions.Limits.MinResponseDataRate = new MinDataRate(100, TimeSpan.FromSeconds(10));
            //    serverOptions.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
            //    serverOptions.Limits.RequestHeadersTimeout = TimeSpan.FromMinutes(1);
            //    serverOptions.ConfigureHttpsDefaults(listenOptions =>
            //    {
            //        listenOptions.SslProtocols = SslProtocols.Tls12;
            //    });
            //});
            #endregion

            var services = builder.Services;

            #region Swagger介面能夠使用權限鎖定功能
            services.AddSwaggerGen(c =>
            {
                var securityScheme = new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer", // must be lower case
                    BearerFormat = "JWT",
                    Reference = new OpenApiReference
                    {
                        Id = JwtBearerDefaults.AuthenticationScheme,
                        Type = ReferenceType.SecurityScheme
                    }
                };
                c.AddSecurityDefinition(securityScheme.Reference.Id, securityScheme);
                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {securityScheme, Array.Empty<string>()}
                });
            });
            #endregion

            #region JwtTokenConfig & AddAuthentication
            var Configuration = builder.Configuration;
            var jwtTokenConfig = Configuration.GetSection("jwtTokenConfig").Get<TokenConfig>();
            services.AddSingleton(jwtTokenConfig);
            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(x =>
            {
                x.RequireHttpsMetadata = true;
                x.SaveToken = true;
                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwtTokenConfig.Issuer,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtTokenConfig.Secret ?? string.Empty)),
                    ValidAudience = jwtTokenConfig.Audience,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(1)
                };
            });
            #endregion

            services.AddSingleton<AuthManagerInterface, AuthManager>();
            services.AddHostedService<RefreshTokenCache>();

            #region Cors設定(前端網頁跨網域時須作此設定)
            services.AddCors(options =>
            {
                options.AddPolicy("AllowAll",
                    builder => { builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader(); });
            });
            #endregion

        }

        /// <summary>
        /// WebApplication_Process
        /// </summary>
        /// <param name="app"></param>
        protected override void WebApplication_Process(WebApplication app)
        {
            base.WebApplication_Process(app);

            //if (app.Environment.IsDevelopment())
            //{
            //    app.UseDeveloperExceptionPage();
            //}

            //app.UseHttpsRedirection();

            //如果有對 app.UseRouting() 和 app.UseEndpoints(...) 的調用，
            //則對 app.UseAuthorization() & app.UseAuthentication() 的調用必須在它們之間進行。
            //app.UseAuthentication()需在app.UseAuthorization() 之前
            #region UseRouting...UseEndpoints
            app.UseRouting();

            #region Cors設定(前端網頁跨網域時須作此設定)
            app.UseCors("AllowAll");
            #endregion
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
            #endregion
        }

    }
}