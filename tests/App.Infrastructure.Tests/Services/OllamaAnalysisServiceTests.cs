using System.Net;
using System.Text;
using SmartNetworkTrafficAnalyzer.Core.Abstractions;
using SmartNetworkTrafficAnalyzer.Infrastructure.Services;
using Xunit;

namespace SmartNetworkTrafficAnalyzer.Infrastructure.Tests.Services;

public class OllamaAnalysisServiceTests
{
    private static readonly ConnectionAnalysisContext TestContext = new(
        RemoteIp: "8.8.8.8",
        ProcessName: "chrome.exe",
        ProcessId: 1234,
        Hostname: "dns.google",
        Country: "US",
        RemotePort: 443,
        Direction: "Outbound",
        BytesIn: 4096,
        BytesOut: 512
    );
    [Fact]
    public async Task GetAvailableModelsAsync_ReturnsModelNamesFromApi()
    {
        var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""
                {
                  "models": [
                    { "name": "llama3.2:3b" },
                    { "name": "mistral:7b" }
                  ]
                }
                """, Encoding.UTF8, "application/json")
        });

        var service = CreateService(handler);

        var models = await service.GetAvailableModelsAsync();

        Assert.Equal(new[] { "llama3.2:3b", "mistral:7b" }, models);
    }

    [Fact]
    public async Task AnalyzeConnectionAsync_UsesUpdatedSelectedModel()
    {
        string? requestBody = null;
        var handler = new StubHttpMessageHandler(request =>
        {
            if (request.RequestUri?.AbsolutePath == "/api/generate")
            {
                requestBody = request.Content?.ReadAsStringAsync().GetAwaiter().GetResult();
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{" + "\"response\":\"ok\"}" , Encoding.UTF8, "application/json")
            };
        });

        var service = CreateService(handler);
        service.SetSelectedModel("llama3.2:3b");

        var result = await service.AnalyzeConnectionAsync(TestContext);

        Assert.Equal("ok", result);
        Assert.NotNull(requestBody);
        Assert.Contains("\"model\":\"llama3.2:3b\"", requestBody);
    }

    [Fact]
    public void SetSelectedModel_PersistsSelectionInSettings()
    {
        var settings = new InMemorySettingsService();
        var service = CreateService(new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)), settings);

        service.SetSelectedModel("mistral:7b");

        Assert.Equal("mistral:7b", service.SelectedModel);
        Assert.Equal("mistral:7b", settings.Get("ollama.model", string.Empty));
    }

    private static OllamaAnalysisService CreateService(HttpMessageHandler handler, ISettingsService? settings = null)
    {
        return new OllamaAnalysisService(
            new HttpClient(handler) { BaseAddress = new Uri("http://localhost:11434") },
            new ConsoleLoggingService(),
            settings ?? new InMemorySettingsService());
    }

    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(handler(request));
        }
    }
}