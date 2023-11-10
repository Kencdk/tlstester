using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using Spectre.Console;
using Spectre.Console.Cli;

namespace TlsTester
{
    internal sealed class ExecuteTlsTestCommand : AsyncCommand<ExecuteTlsTestCommand.Settings>
    {
        private enum TlsTestResult
        {
            UnsupportedOnSystem,
            Failed,
            Succeeded,
            UnknownError,
        }

        public sealed class Settings : CommandSettings
        {
            [Description("Path to search. Defaults to current directory.")]
            [CommandArgument(0, "[hostname]")]
            public string? HostName { get; init; }

            public override ValidationResult Validate()
            {
                if (string.IsNullOrWhiteSpace(HostName))
                {
                    return ValidationResult.Error("HostName is required");
                }

                return base.Validate();
            }
        }

        public async override Task<int> ExecuteAsync([NotNull] CommandContext context, [NotNull] Settings settings)
        {
#pragma warning disable SYSLIB0039 // Type or member is obsolete
#pragma warning disable CS0618 // Type or member is obsolete
            var protocolsToTest = new[]
            {
                SslProtocols.Ssl2,
                SslProtocols.Ssl3,
                SslProtocols.Tls,
                SslProtocols.Tls11,
                SslProtocols.Tls12,
                SslProtocols.Tls13,
            };
#pragma warning restore CS0618 // Type or member is obsolete
#pragma warning restore SYSLIB0039 // Type or member is obsolete

            AnsiConsole.WriteLine($"Validating connections against {settings.HostName}");

            var table = new Table().Centered()
                .AddColumn("Protocol Version")
                .AddColumn("Result");

            await AnsiConsole.Live(table)
                .AutoClear(false)   // Do not remove when done
                .Overflow(VerticalOverflow.Ellipsis) // Show ellipsis when overflowing
                .Cropping(VerticalOverflowCropping.Top) // Crop overflow at top
                .StartAsync(async ctx =>
                {
                    foreach (var protocol in protocolsToTest)
                    {
                        table.AddRow(protocol.ToString(), "[yellow]pending[/]");
                    }

                    ctx.Refresh();

                    for (int i = 0; i < protocolsToTest.Length; i++)
                    {
                        table.UpdateCell(i, 1, "[yellow]Running[/]");
                        ctx.Refresh();
                        var testResult = await TestProtocol(settings.HostName, protocolsToTest[i]);
                        table.UpdateCell(i, 1, ResultToString(testResult));
                        ctx.Refresh();
                    }
                });

            return 0;
        }

        private static string ResultToString(TlsTestResult result)
        {
            return result switch
            {
                TlsTestResult.UnknownError => "[red]Unexpected error[/]",
                TlsTestResult.UnsupportedOnSystem => "[yellow]Version is not supported on this host.[/]",
                TlsTestResult.Failed => "[red]Failed[/]",
                TlsTestResult.Succeeded => "[green]Succeeded[/]",
                _ => throw new NotImplementedException(),
            };
        }

        private static async Task<TlsTestResult> TestProtocol(string hostname, SslProtocols protocol)
        {
            using var tcpClient = new TcpClient(hostname, 443);
            var tcpStream = tcpClient.GetStream();
            using var sslStream = new SslStream(tcpStream, false, null, null, EncryptionPolicy.RequireEncryption);

            try
            {
                await sslStream.AuthenticateAsClientAsync(hostname, null, protocol, true);
                sslStream.Close();
                tcpClient.Close();

                return TlsTestResult.Succeeded;
            }
            catch (AuthenticationException ex) when ((ex.InnerException is Win32Exception win32Exception) && win32Exception.NativeErrorCode == -2146893007)
            {
                return TlsTestResult.Failed;
            }
            catch (AuthenticationException ex) when ((ex.InnerException is Win32Exception win32Exception) && win32Exception.NativeErrorCode == -2146893054)
            {
                // the requested function is not supported - the cipher is disabled on this system.
                return TlsTestResult.Failed;
            }
            catch (Exception)
            {
                return TlsTestResult.UnknownError;
            }
        }
    }
}
