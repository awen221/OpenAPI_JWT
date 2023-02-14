using Microsoft.Extensions.Hosting;

namespace OpenAPI_JWT.Core
{
    /// <summary>
    /// RefreshTokenCache
    /// </summary>
    public class RefreshTokenCache : IHostedService, IDisposable
    {
        private Timer? _timer;
        private readonly AuthManagerInterface _jwtAuthManager;

        /// <summary>
        /// RefreshTokenCache
        /// </summary>
        /// <param name="AuthManagerInterface"></param>
        public RefreshTokenCache(AuthManagerInterface jwtAuthManager)
        {
            _jwtAuthManager = jwtAuthManager;
        }

        private void DoWork(object? state)
        {
            _jwtAuthManager.RemoveExpiredRefreshTokens(DateTime.Now);
        }
        /// <summary>
        /// StartAsync
        /// </summary>
        /// <param name="stoppingToken"></param>
        /// <returns></returns>
        public Task StartAsync(CancellationToken stoppingToken)
        {
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