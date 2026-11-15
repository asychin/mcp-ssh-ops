export const macOsPromptScript = `
on run argv
  try
    set response to display dialog (item 2 of argv) with title (item 1 of argv) default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" cancel button "Cancel"
    return text returned of response
  on error number -128
    error number -128
  end try
end run
`;

export const windowsPromptScript = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class McpSshCredentialPrompt {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct Info {
    public int Size;
    public IntPtr Parent;
    public string Message;
    public string Caption;
    public IntPtr Banner;
  }
  [DllImport("credui.dll", CharSet = CharSet.Unicode)]
  static extern uint CredUIPromptForWindowsCredentialsW(ref Info info, uint error, ref uint package,
    IntPtr input, uint inputSize, out IntPtr output, out uint outputSize, ref bool save, uint flags);
  [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredUnPackAuthenticationBufferW(uint flags, IntPtr buffer, uint size,
    StringBuilder user, ref uint userSize, StringBuilder domain, ref uint domainSize,
    StringBuilder password, ref uint passwordSize);
  public static void Prompt(string title, string message) {
    var info = new Info { Size = Marshal.SizeOf(typeof(Info)), Caption = title, Message = message };
    uint package = 0, size = 0;
    bool save = false;
    IntPtr buffer = IntPtr.Zero;
    StringBuilder password = null;
    try {
      uint result = CredUIPromptForWindowsCredentialsW(ref info, 0, ref package,
        IntPtr.Zero, 0, out buffer, out size, ref save, 1);
      if (result == 1223) { Environment.ExitCode = 1; return; }
      if (result != 0) throw new InvalidOperationException("Credential dialog failed: " + result);
      uint userSize = 0, domainSize = 0, passwordSize = 0;
      CredUnPackAuthenticationBufferW(0, buffer, size, null, ref userSize, null, ref domainSize, null, ref passwordSize);
      if (passwordSize > 16384 || userSize > 16384 || domainSize > 16384)
        throw new InvalidOperationException("Credential result too large");
      var user = new StringBuilder((int)Math.Max(userSize, 1));
      var domain = new StringBuilder((int)Math.Max(domainSize, 1));
      password = new StringBuilder((int)Math.Max(passwordSize, 1));
      if (!CredUnPackAuthenticationBufferW(0, buffer, size, user, ref userSize,
          domain, ref domainSize, password, ref passwordSize))
        throw new InvalidOperationException("Credential result could not be unpacked");
      Console.WriteLine(password.ToString());
    } finally {
      if (password != null) { for (int i = 0; i < password.Length; i++) password[i] = '\\0'; password.Clear(); }
      if (buffer != IntPtr.Zero) {
        for (uint i = 0; i < size; i++) Marshal.WriteByte(buffer, (int)i, 0);
        Marshal.FreeCoTaskMem(buffer);
      }
    }
  }
}
'@
[McpSshCredentialPrompt]::Prompt($env:MCP_SSH_OPS_PROMPT_TITLE, $env:MCP_SSH_OPS_PROMPT_MESSAGE)
if ([Environment]::ExitCode -eq 1) { exit 1 }
} catch {
  [Console]::Error.WriteLine('The native Windows credential dialog failed.')
  exit 2
}
`;
