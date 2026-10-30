// Copyright 2026 the original author or authors.
// Licensed under the Apache License, Version 2.0.
// https://www.apache.org/licenses/LICENSE-2.0
// Distributed on an AS IS BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

public sealed class AnonymousRead : IDisposable {
    internal SafeFileHandle File;
    public bool Opened { get; internal set; }
    public uint Win32Error { get; internal set; }
    public int TokenQueryError { get; internal set; }
    public bool ContextVerified { get; internal set; }
    public string ReadText() {
        if (!Opened) return "";
        using (var stream = new FileStream(File, FileAccess.Read, 4096, false)) {
            stream.Position = 0;
            byte[] bytes = new byte[2048]; int count = stream.Read(bytes, 0, bytes.Length);
            return System.Text.Encoding.UTF8.GetString(bytes, 0, count);
        }
    }
    public void Dispose() { if (File != null) File.Dispose(); }
}

public static class AnonymousReader {
    [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes {
        public uint Length; public IntPtr RootDirectory, ObjectName; public uint Attributes;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr Status, Information; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateAnonymousToken(IntPtr thread);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenThreadToken(IntPtr thread, uint access, bool asSelf, out SafeFileHandle token);
    [DllImport("ntdll.dll")] static extern int NtCreateFile(out SafeFileHandle handle, uint access,
        ref ObjectAttributes attributes, out IoStatus status, IntPtr allocation, uint fileAttributes,
        uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
    [DllImport("ntdll.dll")] static extern uint RtlNtStatusToDosError(int status);

    static int QueryError() {
        SafeFileHandle token;
        if (OpenThreadToken(GetCurrentThread(), 8, true, out token)) { token.Dispose(); return 0; }
        return Marshal.GetLastWin32Error();
    }
    public static string ProcessSid() { using (var id = WindowsIdentity.GetCurrent()) return id.User.Value; }
    public static string AccountSid(string name) { return ((SecurityIdentifier)new NTAccount(name).Translate(typeof(SecurityIdentifier))).Value; }

    public static AnonymousRead Open(string directory, string leaf) {
        if (leaf != Path.GetFileName(leaf) || leaf.IndexOf(':') >= 0 || leaf == "." || leaf == "..")
            throw new ArgumentException("Only one fixture filename is allowed");
        string before = ProcessSid();
        if (QueryError() != 1008) throw new InvalidOperationException("Unexpected pre-existing thread token");
        // This directory handle supplies fixture traversal only. NtCreateFile below
        // still checks the CHILD file's requested data access as anonymous.
        using (var parent = CreateFileW(directory, 0x80000000, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
            if (parent.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr text = Marshal.StringToHGlobalUni(leaf), name = IntPtr.Zero;
            var result = new AnonymousRead();
            try {
                var unicode = new UnicodeString { Length=checked((ushort)(leaf.Length*2)),
                    MaximumLength=checked((ushort)((leaf.Length+1)*2)), Buffer=text };
                name = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
                Marshal.StructureToPtr(unicode, name, false);
                var attr = new ObjectAttributes { Length=(uint)Marshal.SizeOf<ObjectAttributes>(),
                    RootDirectory=parent.DangerousGetHandle(), ObjectName=name,
                    Attributes=0x40 | 0x400 }; // CASE_INSENSITIVE | FORCE_ACCESS_CHECK
                if (!ImpersonateAnonymousToken(GetCurrentThread())) throw new Win32Exception(Marshal.GetLastWin32Error());
                try {
                    result.TokenQueryError = QueryError();
                    IoStatus io;
                    int status = NtCreateFile(out result.File, 0x100001, ref attr, out io,
                        IntPtr.Zero, 0, 7, 1, 0x60, IntPtr.Zero, 0); // SYNCHRONIZE|READ_DATA, FILE_OPEN
                    result.Opened = status >= 0 && result.File != null && !result.File.IsInvalid;
                    result.Win32Error = status < 0 ? RtlNtStatusToDosError(status) : 0;
                }
                finally {
                    if (!RevertToSelf()) Environment.FailFast("Anonymous observer could not revert thread identity");
                }
                result.ContextVerified = result.TokenQueryError == 1347 && QueryError() == 1008 && ProcessSid() == before;
                if (!result.Opened && result.File != null) result.File.Dispose();
                return result;
            }
            finally {
                if (name != IntPtr.Zero) Marshal.FreeHGlobal(name);
                Marshal.FreeHGlobal(text);
            }
        }
    }
}
