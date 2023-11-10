using Spectre.Console.Cli;

namespace TlsTester
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var app = new CommandApp<ExecuteTlsTestCommand>();
            app.Run(args);
        }
    }
}