namespace GHelper.Linux.Platform.Linux;

/// <summary>
/// Interface to the ryzen_smu kernel driver for Curve Optimizer (CO) undervolting.
///
/// Public API mirrors the Windows g-helper PawnIO.RyzenSmuService: SetCoAll / ResetCoAll,
/// plus IsAvailable (analogous to CanSetCoAll / IsInitialized). The backend is different
/// (ryzen_smu sysfs vs. PawnIO), but the SMU protocol and CO semantics are the same.
///
/// CO works via SMU mailbox commands (NOT x86 MSRs):
///   Userspace → ryzen_smu sysfs → PCI config → SMN bus → SMU mailbox → SMU firmware
///
/// The ryzen_smu driver exposes:
///   /sys/kernel/ryzen_smu_drv/rsmu_cmd   - write: trigger RSMU command (blocks until done)
///                                           read: response status (0x01 = OK)
///   /sys/kernel/ryzen_smu_drv/smu_args   - write: set 6x uint32 LE arguments (24 bytes)
///                                           read: response arguments after command
///   /sys/kernel/ryzen_smu_drv/codename   - CPU codename ID from driver
///
/// Protocol (from ryzen_smu drv.c, mutex-serialized in kernel):
///   1. Write 24 bytes to smu_args
///   2. Write 4 bytes to rsmu_cmd - triggers command, blocks until SMU responds
///   3. Read 4 bytes from rsmu_cmd - response status
///   4. Read 24 bytes from smu_args - response data
///
/// Command IDs verified from ZenStates-Core (irusanov/ZenStates-Core):
///   Zen4Settings.cs + DragonRangeSettings.cs (identical RSMU CO commands)
///
/// CO values are NOT persistent - they reset on every reboot.
///
/// Tctl max (CPU temperature limit) uses RSMU SetTctlMax where verified (Raphael /
/// Dragon Range, 0x59). The ASUS firmware rewrites the limit on its own, so
/// StartTctlGuard re-asserts it from a 500 ms PM table poll until StopTctlGuard.
///
/// SAFETY:
///   - Startup validation: sends a read-only GetDldoPsmMargin before allowing writes
///   - Range clamped to [MinCPUUV, MaxCPUUV] (matches Windows CpuInfo.MinCPUUV/MaxCPUUV)
///   - Read-back verification after every write
///   - All SMU interactions logged
///   - Application-level lock (defense-in-depth over kernel mutex)
/// </summary>
public sealed class RyzenSmu
{
    private const string DriverPath = "/sys/kernel/ryzen_smu_drv";
    private const string RsmuCmdPath = DriverPath + "/rsmu_cmd";
    private const string SmuArgsPath = DriverPath + "/smu_args";
    private const string CodenamePath = DriverPath + "/codename";
    private const string VersionPath = DriverPath + "/version";
    private const string PmTablePath = DriverPath + "/pm_table";
    private const string PmTableSizePath = DriverPath + "/pm_table_size";
    private const string PmTableVersionPath = DriverPath + "/pm_table_version";

    // SMU response codes (from ryzen_smu smu.h)
    private const uint SMU_RETURN_OK = 0x01;
    private const uint SMU_RETURN_FAILED = 0xFF;
    private const uint SMU_RETURN_UNKNOWN_CMD = 0xFE;
    private const uint SMU_RETURN_CMD_REJECTED_PREREQ = 0xFD;
    private const uint SMU_RETURN_CMD_REJECTED_BUSY = 0xFC;

    // UV bounds matching Windows PawnIO.CpuInfo.MinCPUUV / MaxCPUUV.
    // BIOS Curve Optimizer range is [-30, +30] but Windows uses [-40, 0]; SMU firmware
    // will reject or clamp values beyond what the silicon accepts.
    public const int MinCPUUV = -40;
    public const int MaxCPUUV = 0;

    // CPU temperature target bounds matching Windows RyzenControl.MinTemp / MaxTemp.
    // MaxTctl is the stock limit: a target at MaxTctl means "no override".
    public const int MinTctl = 75;
    public const int MaxTctl = 98;

    /// <summary>
    /// RSMU command IDs for Curve Optimizer, per CPU generation.
    /// Verified from ZenStates-Core source (Zen3Settings.cs, Zen4Settings.cs, DragonRangeSettings.cs).
    /// </summary>
    private record SmuCommandSet(
        uint SetAllCoreCO,    // SetAllDldoPsmMargin
        uint SetPerCoreCO,    // SetDldoPsmMargin
        uint GetPerCoreCO,    // GetDldoPsmMargin (read-only, used for validation)
        uint? SetTctlMax = null // SetTctlMax (arg0 = degrees C); null = not verified for this CPU
    );

    // ryzen_smu codename IDs (from amkillam/ryzen_smu smu.h enum smu_processor_codename)
    // Command IDs verified from ZenStates-Core source. Startup validation probe
    // (GetDldoPsmMargin) catches wrong command IDs before any writes happen.
    private const int CODENAME_REMBRANDT = 11;     // Zen 3+ APU (Ryzen 6000 mobile)
    private const int CODENAME_VERMEER = 12;       // Zen 3 desktop (Ryzen 5000)
    private const int CODENAME_CEZANNE = 14;       // Zen 3 APU (Ryzen 5000G)
    private const int CODENAME_RAPHAEL = 20;       // Zen 4 desktop + Dragon Range mobile - TESTED
    private const int CODENAME_PHOENIX = 21;       // Zen 4 APU (Ryzen 7040)
    private const int CODENAME_STRIX_POINT = 22;   // Zen 5 mobile (Ryzen AI 300)
    private const int CODENAME_GRANITE_RIDGE = 23; // Zen 5 desktop (Ryzen 9000)
    private const int CODENAME_HAWK_POINT = 24;    // Zen 4 refresh (Ryzen 8000 mobile)
    private const int CODENAME_STRIX_HALO = 26;    // Zen 5 (Ryzen AI 300 HX)

    // Enabled codenames. Startup validation probe ensures safety - if the SMU rejects
    // the GetDldoPsmMargin read, CO disables itself before any writes happen.
    private static readonly Dictionary<int, SmuCommandSet> CommandSets = new()
    {
        // Zen 3 RSMU - ZenStates-Core/SMUSettings/Zen3Settings.cs
        [CODENAME_VERMEER] = new(SetAllCoreCO: 0x0B, SetPerCoreCO: 0x0A, GetPerCoreCO: 0x7C),
        [CODENAME_CEZANNE] = new(SetAllCoreCO: 0x0B, SetPerCoreCO: 0x0A, GetPerCoreCO: 0x7C),
        [CODENAME_REMBRANDT] = new(SetAllCoreCO: 0x0B, SetPerCoreCO: 0x0A, GetPerCoreCO: 0x7C),

        // Zen 4 RSMU - ZenStates-Core/SMUSettings/Zen4Settings.cs + DragonRangeSettings.cs (identical)
        // SetTctlMax 0x59 from Zen4Settings.cs (Rsmu.SMU_MSG_SetTctlMax), verified on Dragon Range
        // (GX650PY). ryzenadj rejects this CPU, and Windows' MP1 0x3F needs root-only mp1_smu_cmd.
        [CODENAME_RAPHAEL] = new(SetAllCoreCO: 0x07, SetPerCoreCO: 0x06, GetPerCoreCO: 0xD5, SetTctlMax: 0x59),
        [CODENAME_PHOENIX] = new(SetAllCoreCO: 0x07, SetPerCoreCO: 0x06, GetPerCoreCO: 0xD5),
        [CODENAME_HAWK_POINT] = new(SetAllCoreCO: 0x07, SetPerCoreCO: 0x06, GetPerCoreCO: 0xD5),

        // Zen 5 RSMU - ZenStates-Core/SMUSettings/Zen5Settings.cs
        [CODENAME_GRANITE_RIDGE] = new(SetAllCoreCO: 0x07, SetPerCoreCO: 0x06, GetPerCoreCO: 0xD5),
        [CODENAME_STRIX_POINT] = new(SetAllCoreCO: 0x07, SetPerCoreCO: 0x06, GetPerCoreCO: 0xD5),
        [CODENAME_STRIX_HALO] = new(SetAllCoreCO: 0x07, SetPerCoreCO: 0x06, GetPerCoreCO: 0xD5),
    };

    // PM table layouts with a verified THM limit offset (float index). The
    // read-back lets the Tctl guard rewrite only when the firmware has changed it.
    private static readonly Dictionary<uint, int> PmTableThmLimitIndex = new()
    {
        [0x00540005] = 10, // Raphael/Dragon Range: [10] THM limit, [11] THM value (Tctl)
    };

    // Tctl guard: the ASUS firmware rewrites the THM limit on its own (98/92 C,
    // ~17 s cycle on GX650PY), so a single SetTctlMax does not hold.
    private const int TctlGuardIntervalMs = 500;
    private const int TctlGuardBlindTicks = 4; // unknown PM table: rewrite every 2 s

    private SmuCommandSet? _commands;
    private int _codename = -1;
    private readonly object _smuLock = new();  // Defense-in-depth over kernel mutex
    private readonly object _guardLock = new();
    private Timer? _tctlGuard;
    private int _tctlTarget;
    private int _tctlGuardTicks;
    private int _tctlReasserts;
    private int? _tctlStock;

    /// <summary>Whether the driver is present, the CPU is supported, and validation passed.</summary>
    public bool IsAvailable { get; private set; }

    /// <summary>Human-readable reason if IsAvailable is false.</summary>
    public string? UnavailableReason { get; private set; }

    /// <summary>ryzen_smu codename ID.</summary>
    public int Codename => _codename;

    /// <summary>Whether the SMU can set the CPU temperature limit (SetTctlMax).</summary>
    public bool CanSetTctlMax => IsAvailable && _commands?.SetTctlMax != null;

    /// <summary>Target the Tctl guard is holding, or null when it is off.</summary>
    public int? TctlGuardTarget
    {
        get
        {
            lock (_guardLock)
                return _tctlGuard != null ? _tctlTarget : null;
        }
    }

    public RyzenSmu()
    {
        try
        {
            if (!Directory.Exists(DriverPath))
            {
                UnavailableReason = "ryzen_smu driver not loaded";
                Helpers.Logger.WriteLine("RyzenSmu: " + UnavailableReason);
                return;
            }

            // Check write permissions on command files
            if (!IsWritable(RsmuCmdPath) || !IsWritable(SmuArgsPath))
            {
                UnavailableReason = "no write permission on ryzen_smu files (need root or udev rule)";
                Helpers.Logger.WriteLine("RyzenSmu: " + UnavailableReason);
                return;
            }

            var codenameStr = SysfsHelper.ReadAttribute(CodenamePath);
            if (codenameStr == null || !int.TryParse(codenameStr, out _codename))
            {
                UnavailableReason = "could not read CPU codename from driver";
                Helpers.Logger.WriteLine("RyzenSmu: " + UnavailableReason);
                return;
            }

            if (!CommandSets.TryGetValue(_codename, out _commands))
            {
                UnavailableReason = $"unsupported CPU codename {_codename}";
                Helpers.Logger.WriteLine("RyzenSmu: " + UnavailableReason);
                return;
            }

            var version = SysfsHelper.ReadAttribute(VersionPath);
            string codenameLabel = _codename switch
            {
                CODENAME_REMBRANDT => "Rembrandt (Zen 3+ APU)",
                CODENAME_VERMEER => "Vermeer (Zen 3)",
                CODENAME_CEZANNE => "Cezanne (Zen 3 APU)",
                CODENAME_RAPHAEL => "Raphael/DragonRange (Zen 4)",
                CODENAME_PHOENIX => "Phoenix (Zen 4 APU)",
                CODENAME_STRIX_POINT => "Strix Point (Zen 5 mobile)",
                CODENAME_GRANITE_RIDGE => "Granite Ridge (Zen 5)",
                CODENAME_HAWK_POINT => "Hawk Point (Zen 4 refresh)",
                CODENAME_STRIX_HALO => "Strix Halo (Zen 5)",
                _ => $"unknown ({_codename})"
            };
            Helpers.Logger.WriteLine($"RyzenSmu: codename={_codename} ({codenameLabel}), SMU firmware={version}");

            // Validate: send a read-only GetDldoPsmMargin for CCD0/core0.
            // If the SMU rejects this with "unknown command", the command set is wrong
            // and we must NOT attempt any writes.
            if (!ValidateCommandSet())
            {
                UnavailableReason = "SMU command validation failed - CO commands not accepted by firmware";
                Helpers.Logger.WriteLine("RyzenSmu: " + UnavailableReason);
                _commands = null; // Prevent any further use
                return;
            }

            IsAvailable = true;
            Helpers.Logger.WriteLine("RyzenSmu: validation passed, Curve Optimizer available" +
                (CanSetTctlMax ? $", Tctl max available (PM table version 0x{ReadPmTableVersion() ?? 0:X8})" : ""));
        }
        catch (Exception ex)
        {
            UnavailableReason = $"initialization error: {ex.Message}";
            Helpers.Logger.WriteLine("RyzenSmu: init failed", ex);
        }
    }

    /// <summary>
    /// Validate the command set by sending a read-only GetDldoPsmMargin.
    /// This is non-destructive - it only reads the current CO value for CCD0/core0.
    /// Returns true if the SMU accepted the command (status = OK).
    /// </summary>
    private bool ValidateCommandSet()
    {
        if (_commands == null)
            return false;

        Helpers.Logger.WriteLine("RyzenSmu: validating with GetDldoPsmMargin (read-only) for CCD0/core0...");

        // CCD0, core0 mask
        uint coreMask = 0; // (0 << 28) | (0 << 20) = 0

        var (status, _) = SendRsmuCommandRaw(_commands.GetPerCoreCO, coreMask);

        if (status == SMU_RETURN_OK)
        {
            Helpers.Logger.WriteLine("RyzenSmu: validation OK - GetDldoPsmMargin accepted");
            return true;
        }
        else if (status == SMU_RETURN_UNKNOWN_CMD)
        {
            Helpers.Logger.WriteLine($"RyzenSmu: VALIDATION FAILED - SMU returned 'unknown command' (0x{status:X2}). " +
                "Command IDs may not match this firmware version. Disabling CO to prevent damage.");
            return false;
        }
        else
        {
            Helpers.Logger.WriteLine($"RyzenSmu: validation returned unexpected status 0x{status:X2}. " +
                "Disabling CO as a safety precaution.");
            return false;
        }
    }

    /// <summary>
    /// Set Curve Optimizer offset for ALL cores. Mirrors Windows RyzenSmuService.SetCoAll.
    /// </summary>
    /// <param name="offset">CO offset, clamped to [MinCPUUV, MaxCPUUV]. Negative = undervolt.</param>
    /// <returns>True if the SMU accepted the command. Read-back is logged; a mismatch
    /// does NOT flip the return to false (the write itself still succeeded).</returns>
    public bool SetCoAll(int offset)
    {
        if (!IsAvailable || _commands == null)
            return false;

        offset = Math.Clamp(offset, MinCPUUV, MaxCPUUV);
        uint encoded = EncodeCOMargin(offset);

        Helpers.Logger.WriteLine($"RyzenSmu: SetCoAll offset={offset} encoded=0x{encoded:X4}");

        bool ok = SendRsmuCommand(_commands.SetAllCoreCO, encoded);
        if (!ok)
        {
            Helpers.Logger.WriteLine("RyzenSmu: SetCoAll FAILED");
            return false;
        }

        // Read-back verification: check core 0 to confirm the value took effect
        int? readback = GetPerCoreCO(0, 0);
        if (readback != null)
        {
            Helpers.Logger.WriteLine($"RyzenSmu: SetCoAll readback CCD0/core0 = {readback}");
            if (readback != offset)
                Helpers.Logger.WriteLine($"RyzenSmu: WARNING - readback ({readback}) differs from requested ({offset})");
        }
        else
        {
            Helpers.Logger.WriteLine("RyzenSmu: SetCoAll readback failed (write may still have succeeded)");
        }

        return true;
    }

    /// <summary>
    /// Set Curve Optimizer offset for a single core. Kept for future per-core UI
    /// (no Windows public analogue; internal helper).
    /// </summary>
    /// <param name="ccd">CCD index (0-based)</param>
    /// <param name="core">Core index within CCD (0-7)</param>
    /// <param name="offset">CO offset, clamped to [MinCPUUV, MaxCPUUV]. Negative = undervolt.</param>
    public bool SetPerCoreCO(int ccd, int core, int offset)
    {
        if (!IsAvailable || _commands == null)
            return false;

        offset = Math.Clamp(offset, MinCPUUV, MaxCPUUV);
        uint encoded = EncodeCOMargin(offset);

        // Bit layout (verified from ZenStates-Core Cpu.cs MakeCoreMask for Family > 17h):
        //   [31:28] = CCD index
        //   [23:20] = core index within CCD (mod 8)
        //   [15:0]  = CO margin (16-bit two's complement)
        uint coreMask = ((uint)ccd << 28) | ((uint)(core % 8) << 20);
        uint arg = (coreMask & 0xFFF00000) | encoded;

        Helpers.Logger.WriteLine($"RyzenSmu: SetPerCoreCO ccd={ccd} core={core} offset={offset} arg=0x{arg:X8}");

        bool ok = SendRsmuCommand(_commands.SetPerCoreCO, arg);
        if (!ok)
        {
            Helpers.Logger.WriteLine($"RyzenSmu: SetPerCoreCO ccd={ccd} core={core} FAILED");
            return false;
        }

        // Read-back verification
        int? readback = GetPerCoreCO(ccd, core);
        if (readback != null)
        {
            Helpers.Logger.WriteLine($"RyzenSmu: SetPerCoreCO readback CCD{ccd}/core{core} = {readback}");
            if (readback != offset)
                Helpers.Logger.WriteLine($"RyzenSmu: WARNING - readback ({readback}) differs from requested ({offset})");
        }

        return true;
    }

    /// <summary>
    /// Read the current CO offset for a single core (non-destructive).
    /// </summary>
    /// <returns>The CO offset value, or null on failure.</returns>
    public int? GetPerCoreCO(int ccd, int core)
    {
        if (!IsAvailable || _commands == null)
            return null;

        uint coreMask = ((uint)ccd << 28) | ((uint)(core % 8) << 20);

        var (status, results) = SendRsmuCommandRaw(_commands.GetPerCoreCO, coreMask);
        if (status != SMU_RETURN_OK || results == null)
            return null;

        // Decode args[0] as a 16-bit two's complement value (matches write encoding).
        // SMU firmware fills only the low 16 bits with the CO margin; upper bits are
        // not guaranteed to be sign-extended, so a raw cast to int32 would turn -22
        // (0xFFEA) into 65514. Sign-extend via a short cast.
        short margin = (short)(results[0] & 0xFFFF);
        return margin;
    }

    /// <summary>
    /// Reset CO for all cores to 0 (no offset). Mirrors Windows convention of calling
    /// SetCoAll(0) through ModeControl.ResetRyzen.
    /// </summary>
    public bool ResetCoAll()
    {
        Helpers.Logger.WriteLine("RyzenSmu: resetting all-core CO to 0");
        return SetCoAll(0);
    }

    /// <summary>
    /// Set the CPU temperature limit (Tctl max) once. No-op on CPUs without a
    /// verified SetTctlMax command. Use <see cref="StartTctlGuard"/> to hold it.
    /// </summary>
    /// <param name="celsius">Limit in degrees C, clamped to [MinTctl, MaxTctl].</param>
    public bool SetTctlMax(int celsius)
    {
        if (!CanSetTctlMax)
            return false;
        celsius = Math.Clamp(celsius, MinTctl, MaxTctl);
        bool ok = SendRsmuCommand(_commands!.SetTctlMax!.Value, (uint)celsius);
        if (!ok)
            Helpers.Logger.WriteLine($"RyzenSmu: SetTctlMax {celsius}C FAILED");
        return ok;
    }

    /// <summary>
    /// Read the current THM limit from the PM table. Null when the table is
    /// unreadable or its layout is not verified.
    /// </summary>
    public float? GetTctlMax()
    {
        try
        {
            uint? version = ReadPmTableVersion();
            if (version == null || !PmTableThmLimitIndex.TryGetValue(version.Value, out int index))
                return null;
            var sizeBytes = ReadSysfsBytes(PmTableSizePath, 8);
            int size = sizeBytes.Length >= 8 ? (int)BitConverter.ToUInt64(sizeBytes, 0) : 0;
            if (size < (index + 1) * 4)
                return null;
            var table = ReadSysfsBytes(PmTablePath, size);
            if (table.Length < (index + 1) * 4)
                return null;
            return BitConverter.ToSingle(table, index * 4);
        }
        catch
        {
            return null;
        }
    }

    private static uint? ReadPmTableVersion()
    {
        try
        {
            var bytes = ReadSysfsBytes(PmTableVersionPath, 4);
            return bytes.Length < 4 ? null : BitConverter.ToUInt32(bytes, 0);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Hold the CPU temperature limit at <paramref name="celsius"/>: write it now,
    /// then poll the PM table every 500 ms and rewrite when the firmware has
    /// changed it. A target at MaxTctl (stock) stops the guard instead.
    /// </summary>
    public bool StartTctlGuard(int celsius)
    {
        if (!CanSetTctlMax)
            return false;
        celsius = Math.Clamp(celsius, MinTctl, MaxTctl);
        if (celsius >= MaxTctl)
        {
            StopTctlGuard();
            return true;
        }

        lock (_guardLock)
        {
            // Limit the firmware had before the first write; Stop restores it.
            if (_tctlGuard == null)
            {
                float? stock = GetTctlMax();
                _tctlStock = stock != null ? (int)Math.Round(stock.Value) : null;
            }
            bool ok = SetTctlMax(celsius);
            float? readback = GetTctlMax();
            Helpers.Logger.WriteLine($"RyzenSmu: Tctl guard {(_tctlGuard != null ? "retarget" : "start")} " +
                $"{celsius}C (write {(ok ? "OK" : "FAILED")}, readback {(readback?.ToString("0.#") ?? "n/a")})");
            _tctlTarget = celsius;
            _tctlGuardTicks = 0;
            _tctlReasserts = 0;
            _tctlGuard ??= new Timer(_ => TctlGuardTick(), null, TctlGuardIntervalMs, TctlGuardIntervalMs);
            return ok;
        }
    }

    /// <summary>
    /// Stop the Tctl guard and restore the limit read before it started
    /// (MaxTctl when the PM table is unreadable). No-op when the guard is not running.
    /// </summary>
    public void StopTctlGuard()
    {
        lock (_guardLock)
        {
            if (_tctlGuard == null)
                return;
            _tctlGuard.Dispose();
            _tctlGuard = null;
            int restore = _tctlStock ?? MaxTctl;
            bool ok = SetTctlMax(restore);
            Helpers.Logger.WriteLine($"RyzenSmu: Tctl guard stop after {_tctlReasserts} re-assert(s), " +
                $"restore {restore}C {(ok ? "OK" : "FAILED")}");
        }
    }

    private void TctlGuardTick()
    {
        // TryEnter: a tick that overlaps a slow SMU call or a Stop just skips.
        if (!Monitor.TryEnter(_guardLock))
            return;
        try
        {
            if (_tctlGuard == null)
                return;
            float? current = GetTctlMax();
            if (current != null)
            {
                if (Math.Abs(current.Value - _tctlTarget) < 0.5f)
                    return;
            }
            else if (++_tctlGuardTicks % TctlGuardBlindTicks != 0)
            {
                return;
            }

            bool ok = SetTctlMax(_tctlTarget);
            _tctlReasserts++;
            // Firmware rewrites every ~17 s: log the first and then every 20th.
            if (_tctlReasserts % 20 == 1 || !ok)
                Helpers.Logger.WriteLine($"RyzenSmu: Tctl guard re-assert {_tctlTarget}C " +
                    $"(was {(current?.ToString("0.#") ?? "unknown")}, {(ok ? "OK" : "FAILED")}, count {_tctlReasserts})");
        }
        catch (Exception ex)
        {
            Helpers.Logger.WriteLine("RyzenSmu: Tctl guard tick failed", ex);
        }
        finally
        {
            Monitor.Exit(_guardLock);
        }
    }

    public bool IsIGpuSupported => false;

    public bool SetIGpuCoAll(int offset)
    {
        if (!IsIGpuSupported)
            return false;
        return false;
    }

    /// <summary>
    /// Encode a CO margin for the SMU.
    /// Verified from ZenStates-Core Utils.cs MakePsmMarginArg:
    ///   Negative: 16-bit two's complement (e.g., -22 → 0xFFEA)
    ///   Positive: raw value (e.g., +5 → 0x0005)
    /// </summary>
    private static uint EncodeCOMargin(int margin)
    {
        if (margin < 0)
            return (uint)((0x10000 + margin) & 0xFFFF);
        return (uint)(margin & 0xFFFF);
    }

    /// <summary>
    /// Send an RSMU command, returning only success/failure.
    /// </summary>
    private bool SendRsmuCommand(uint command, uint arg0)
    {
        var (status, _) = SendRsmuCommandRaw(command, arg0);
        return status == SMU_RETURN_OK;
    }

    /// <summary>
    /// Send an RSMU command and return the raw status + response arguments.
    /// Thread-safe via application-level lock (kernel also serializes internally).
    ///
    /// Protocol (verified from ryzen_smu drv.c):
    ///   1. Write 24 bytes to smu_args (6x uint32 LE)
    ///   2. Write 4 bytes to rsmu_cmd (triggers command, blocks until SMU responds)
    ///   3. Read 4 bytes from rsmu_cmd (response status)
    ///   4. Read 24 bytes from smu_args (response data)
    /// </summary>
    private (uint status, uint[]? results) SendRsmuCommandRaw(uint command, uint arg0)
    {
        lock (_smuLock)
        {
            try
            {
                // Step 1: Write arguments (6x uint32 = 24 bytes, little-endian)
                var argsBytes = new byte[24];
                BitConverter.TryWriteBytes(argsBytes.AsSpan(0, 4), arg0);
                // args[1..5] remain 0

                File.WriteAllBytes(SmuArgsPath, argsBytes);

                // Step 2: Write command (triggers SMU execution, blocks)
                var cmdBytes = new byte[4];
                BitConverter.TryWriteBytes(cmdBytes.AsSpan(0, 4), command);
                File.WriteAllBytes(RsmuCmdPath, cmdBytes);

                // Step 3: Read response status.
                // sysfs files report st_size=4096 but only yield 4 actual bytes,
                // so File.ReadAllBytes (which trusts stream length) throws
                // "Unable to read beyond the end of the stream". Use fixed-size
                // buffer reads instead.
                var respBytes = ReadSysfsBytes(RsmuCmdPath, 4);
                if (respBytes.Length < 4)
                {
                    Helpers.Logger.WriteLine($"RyzenSmu: short response from rsmu_cmd ({respBytes.Length} bytes)");
                    return (0, null);
                }

                uint status = BitConverter.ToUInt32(respBytes, 0);

                if (status != SMU_RETURN_OK)
                {
                    string statusName = status switch
                    {
                        SMU_RETURN_FAILED => "FAILED",
                        SMU_RETURN_UNKNOWN_CMD => "UNKNOWN_CMD",
                        SMU_RETURN_CMD_REJECTED_PREREQ => "REJECTED_PREREQ",
                        SMU_RETURN_CMD_REJECTED_BUSY => "REJECTED_BUSY",
                        _ => $"0x{status:X2}"
                    };
                    Helpers.Logger.WriteLine($"RyzenSmu: command 0x{command:X2} returned {statusName}");
                    return (status, null);
                }

                // Step 4: Read response arguments
                var resultBytes = ReadSysfsBytes(SmuArgsPath, 24);
                uint[]? results = null;
                if (resultBytes.Length >= 24)
                {
                    results = new uint[6];
                    for (int i = 0; i < 6; i++)
                        results[i] = BitConverter.ToUInt32(resultBytes, i * 4);
                }

                return (status, results);
            }
            catch (UnauthorizedAccessException ex)
            {
                Helpers.Logger.WriteLine($"RyzenSmu: permission denied for command 0x{command:X2} - need root or udev rule", ex);
                return (0, null);
            }
            catch (Exception ex)
            {
                Helpers.Logger.WriteLine($"RyzenSmu: command 0x{command:X2} exception", ex);
                return (0, null);
            }
        }
    }

    /// <summary>
    /// Read exactly <paramref name="count"/> bytes from a sysfs pseudo-file.
    /// sysfs files report st_size=4096 but contain far fewer bytes, so
    /// File.ReadAllBytes (which pre-allocates based on stream length) fails with
    /// "Unable to read beyond the end of the stream". This method opens the file
    /// and reads up to <paramref name="count"/> bytes without trusting the reported size.
    /// </summary>
    private static byte[] ReadSysfsBytes(string path, int count)
    {
        var buf = new byte[count];
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        int total = 0;
        while (total < count)
        {
            int n = fs.Read(buf, total, count - total);
            if (n == 0)
                break;
            total += n;
        }
        if (total == count)
            return buf;
        var trimmed = new byte[total];
        Array.Copy(buf, trimmed, total);
        return trimmed;
    }

    /// <summary>Check if a sysfs file is writable by the current user.</summary>
    private static bool IsWritable(string path)
    {
        try
        {
            if (!File.Exists(path))
                return false;
            using var fs = File.Open(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Format an SMU status code for display.</summary>
    public static string FormatStatus(uint status) => status switch
    {
        SMU_RETURN_OK => "OK",
        SMU_RETURN_FAILED => "Failed",
        SMU_RETURN_UNKNOWN_CMD => "Unknown command",
        SMU_RETURN_CMD_REJECTED_PREREQ => "Rejected (prerequisite)",
        SMU_RETURN_CMD_REJECTED_BUSY => "Rejected (busy)",
        _ => $"Unknown (0x{status:X2})"
    };

}
