using Microsoft.Extensions.Hosting;

namespace OpenAPI_JWT.Core
{

    /// <summary>
    /// RefreshTokenCache
    /// </summary>
    public class JwtAuthenticationRefreshTokenCache : IHostedService, IDisposable
    {

        private Timer? _timer { set; get; }
        private JwtAuthenticationManagerInterface _jwtAuthManager { set; get; }

        /// <summary>
        /// RefreshTokenCache
        /// </summary>
        /// <param name="AuthManagerInterface"></param>
        public JwtAuthenticationRefreshTokenCache(JwtAuthenticationManagerInterface jwtAuthManager)
        {
            _jwtAuthManager = jwtAuthManager;
        }
        

        /// <summary>
        /// StartAsync
        /// </summary>
        /// <param name="stoppingToken"></param>
        /// <returns></returns>
        public Task StartAsync(CancellationToken stoppingToken)
        {
            void DoWork(object? state)
            {
                _jwtAuthManager.RemoveExpiredRefreshTokens(DateTime.Now);
            }
            // remove expired refresh tokens from cache every minute
            _timer = new Timer(DoWork, null, TimeSpan.Zero, TimeSpan.FromMinutes(1));
            return Task.CompletedTask;
        }
        /// <summary>
        /// StopAsync
        /// </summary>
        /// <param name="stoppingToken"></param>
        /// <returns></returns>
        public Task StopAsync(CancellationToken stoppingToken)
        {
            _timer?.Change(Timeout.Infinite, 0);
            return Task.CompletedTask;
        }


        /// <summary>
        /// Dispose
        /// </summary>
        public void Dispose()
        {
            _timer?.Dispose();
        }

    }

}