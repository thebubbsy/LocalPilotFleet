using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace LocalPilotService
{
    public static class JobObjectInterop
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetInformationJobObject(
            IntPtr hJob,
            JobObjectInfoClass JobObjectInformationClass,
            IntPtr lpJobObjectInformation,
            uint cbJobObjectInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        public enum JobObjectInfoClass
        {
            ExtendedLimitInformation = 9,
            CpuRateControlInformation = 15
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryLimit;
            public UIntPtr PeakJobMemoryLimit;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
        {
            public uint ControlFlags;
            public uint CpuRate;
        }

        public const uint JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200;
        public const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
        public const uint JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x00000001;
        public const uint JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x00000004;

        public static IntPtr CreateHardenedJobObject(int maxCpuPercent = 5, int maxMemoryMb = 150)
        {
            IntPtr hJob = CreateJobObject(IntPtr.Zero, "LocalPilotFleet_JobObject_" + Process.GetCurrentProcess().Id);
            if (hJob == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            try
            {
                // Memory Quota: 150 MB
                var extendedLimit = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                extendedLimit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
                ulong memBytes = (ulong)maxMemoryMb * 1024 * 1024;
                extendedLimit.JobMemoryLimit = new UIntPtr(memBytes);
                extendedLimit.ProcessMemoryLimit = new UIntPtr(memBytes);

                int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                IntPtr pExtendedLimit = Marshal.AllocHGlobal(length);
                Marshal.StructureToPtr(extendedLimit, pExtendedLimit, false);
                SetInformationJobObject(hJob, JobObjectInfoClass.ExtendedLimitInformation, pExtendedLimit, (uint)length);
                Marshal.FreeHGlobal(pExtendedLimit);

                // CPU Quota: 5% hard cap (CpuRate is in 1/100 of 1% e.g. 500 = 5.0%)
                var cpuRate = new JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
                {
                    ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                    CpuRate = (uint)(maxCpuPercent * 100)
                };

                int cpuLength = Marshal.SizeOf(typeof(JOBOBJECT_CPU_RATE_CONTROL_INFORMATION));
                IntPtr pCpuRate = Marshal.AllocHGlobal(cpuLength);
                Marshal.StructureToPtr(cpuRate, pCpuRate, false);
                SetInformationJobObject(hJob, JobObjectInfoClass.CpuRateControlInformation, pCpuRate, (uint)cpuLength);
                Marshal.FreeHGlobal(pCpuRate);
            }
            catch
            {
                // Graceful degradation if OS limits cannot be applied
            }

            return hJob;
        }

        public static bool AssignProcess(IntPtr hJob, IntPtr hProcess)
        {
            if (hJob == IntPtr.Zero || hProcess == IntPtr.Zero) return false;
            return AssignProcessToJobObject(hJob, hProcess);
        }
    }
}
