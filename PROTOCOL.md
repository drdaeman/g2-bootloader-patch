# UART2 bootloader RAM protocol

*NOTE:* This is an LLM-generated document, reviewed by a human.

The [loader](src/bootloader.c) lets the host stop boot, upload a small RAM
program, and run it. It can also select an alternate main-application image for
the current boot only. The host must send CONTINUE to release boot. The protocol
has no commands to write firmware images or files.

The supported target uses these versions:

- Bootloader: **2.3.2.14**
- Main application: **2.4.0.24**
- Hardware: **5**
- Case: **1.2.57**

Use the bootloader and host tools from the same source version.
Select the target temple with `boot.py --side left|right` or
`flash.py --side left|right --verify-port PORT`. The case uses the same stock
reset waveform for each temple.

[flash.py](tools/flash.py) installs the patch through stock BLE authentication
and OTA. It does not require Faceclaw patches or an HMAC diagnostic endpoint.
The optional `--verify-port` argument selects a case serial port for
verification. This check uploads and runs [checksum.c](src/examples/checksum.c)
to read the bootloader CRC through the RAM ABI below. It adds no protocol
commands. Verification requires the `make all` build files. The tool checks
these files before OTA starts.

## Packet format

All offsets start at zero. Integer fields are unsigned and little-endian.
Checksums are byte sums modulo 256. ASCII markers are literal bytes.
The protocol has no escaping, sequence numbers, or retransmission.
HOLD and OKAY use HMAC. Later commands and replies have no MAC.

HELO contains the protocol version as a little-endian `uint32_t` at bytes 12–15.
The current version is **`0x00000001`**, sent as `01 00 00 00`.
Reject an unsupported version before sending HOLD. Its challenge starts at byte 16.
No other packet contains the challenge.

The current implementation does not use a random number generator. The handshake
challenge is `tick XOR 0x32524c47`, where `tick` is the boot tick count. It can
repeat after a reboot, so a captured handshake can be replayed when the challenge
repeats, even with a private HMAC key. Hardware RNG support is not implemented.

| Direction | Layout | Checksum |
|---|---|---|
| Host/case → temple, 25 bytes (HOLD) | `7E 00 01 14`, `HOLD`, tag[16], sum[1] | `25 + 0x7D + sum(bytes[0:24])` |
| Host/case → temple, 9 bytes (CONT) | `7E 00 01 04`, `CONT`, sum[1] | `9 + 0x7D + sum(bytes[0:8])` |
| Temple → host/case, 21 bytes (HELO) | `5A A5 FF 10 00 01 03 0C`, `HELO`, version[4], challenge[4], sum[1] | `14 + sum(bytes[4:20])` |
| Temple → host/case, 29 bytes (OKAY) | `5A A5 FF 18 00 01 03 14`, `OKAY`, tag[16], sum[1] | `22 + sum(bytes[4:28])` |
| Temple → host/case, 13 bytes (RLSD) | `5A A5 FF 08 00 01 03 04`, `RLSD`, sum[1] | `6 + sum(bytes[4:12])` |
| Host/case → temple, 32 bytes | `7E 00 01 1B`, `RQST`, operation[1], payload[22], sum[1] | `32 + 0x7D + sum(bytes[0:31])` |
| Temple → host/case, 32 bytes | `5A A5 FF 1B 00 01 03 17`, `RESP`, kind[1], status[1], data[16], reserved[1], sum[1] | `25 + sum(bytes[4:31])` |

In `bytes[a:b]`, the range includes byte `a` and excludes byte `b`.
Set unused payload bytes to zero. Replies contain zeros in unused data bytes
and reserved byte 30. Before the next request, check the full fixed prefix,
length, checksum, expected reply kind, and applicable status.
Loader commands and replies contain no nonce or sequence number.

The reference implementations are
[handshake.py](tools/g2patch/handshake.py) and
[protocol.py](tools/g2patch/protocol.py).

## Handshake key and tags

The key is the UTF-8 value of `G2_BOOT_KEY`. If this variable is absent, the key
is `DEFAULTNOTSECRET`. An empty value is not allowed. Set the same value when
you build the images and run the host tools. Run `make` after a key change.
The build generates `build/auth_key.h` and embeds the key in the temple image.
The host computes HOLD and verifies OKAY. The case relay contains no key.

The default key is public. It does not restrict access. A private override is
also present in the compiled temple image; this scheme does not protect it from
someone who can read those images.

HOLD and OKAY each contain the first 16 bytes of HMAC-SHA-256 over this input:

| Offset | Bytes | Value |
|---|---|---|
| 0 | 6 | ASCII `G2BOOT` |
| 6 | 4 | Protocol version, little-endian |
| 10 | 4 | HELO challenge, little-endian |
| 14 | 4 | ASCII `HOLD` or `OKAY`, matching the packet |

The different markers give each direction a different tag. Check the full tag
before accepting the packet. Headers and byte checksums are checked separately.
See [auth.h](src/auth.h) and [auth.py](tools/g2patch/auth.py).

A successful handshake does not authenticate later traffic. CONT, RLSD, RQST,
and RESP contain neither a challenge nor an HMAC tag. RUN is not idempotent;
its no-retry rule still applies.

## Claim and release

A claim keeps boot on hold until the host sends CONTINUE.

| Order | Direction | Marker | Meaning |
|---|---|---|---|
| 1 | Temple → host | `HELO` | One boot beacon with the version and challenge |
| 2 | Host → temple | `HOLD` | Claim with the HOLD HMAC tag |
| 3 | Temple → host | `OKAY` | Claim acknowledgment with the OKAY HMAC tag |
| 4 | Host → temple | `CONT` | CONTINUE |
| 5 | Temple → host | `RLSD` | Release acknowledgment |

Verify OKAY with the HELO challenge and key before you send loader commands. The loader sets the hold
before it transmits OKAY. If this transmission fails, boot stays on hold and
the loader accepts only CONTINUE.

On CONTINUE, the loader tries to transmit RLSD. It then clears the hold, even
if the transmission fails. RLSD confirms release. Check separately that the
main application starts.

The worker sends the beacon without an initial delay. After worker creation,
the manager waits **512 ticks (500 ms at 1024 Hz)** before it checks the hold.
The worker has no separate receive deadline. The manager has higher priority
than the worker. Send HOLD within this window.

Without a claim, the manager removes the worker, returns UART control to the
stock code, and continues boot. Active UART2 ownership or incompatible
initialization can prevent the probe. Shared UART power status alone does not
prevent it.

After a claim, there is no session timeout or automatic release.
The loader accepts CONTINUE in the command loop and in the release loop after
a failure. CONTINUE cannot interrupt a program. During LOAD or an OUTPUT_ACK/INPUT_DATA
wait, CONTINUE causes a failure because the loader expects a different packet.
This CONTINUE packet does not clear the hold. Send another CONTINUE when the
loader reaches the release loop. If a program does not return, the loader may
never process CONTINUE.

The host release procedure permits up to three CONTINUE exchanges before it
requires RLSD. These exchanges can receive a pending reply and stop an active
transaction. The host sends the next CONTINUE only after a valid reply.
It does not retry transport failures or repeat RUN.

## Loader requests and replies

The request operation is byte 8. Its payload starts at byte 9.

| Operation | Value | Payload fields at absolute byte offsets |
|---|---|---|
| LOAD | 1 | 9: length `u16`; 11: entry offset `u16`; 13: arg0 `u32`; 17: arg1 `u32`; 21: image CRC32 `u32`; 25–30: zero |
| DATA | 2 | 9: count `u8`; 10: count data bytes; remaining bytes through 30: zero |
| RUN | 3 | All zero |
| OUTPUT_ACK | 4 | All zero |
| INPUT_DATA | 5 | 9: count `u8`, 0–16; 10–25: data padded to 16 bytes; 26: data CRC32 `u32`; 30: zero |
| BOOT | 6 | 9: vector table address `u32`, or 0 to clear; 13–30: zero |

The program length must be an even number from **2 to 512 bytes**.
The entry offset must be even and less than the program length. The loader
sets the Thumb bit. Each DATA packet contains **1–16 bytes**. The count must
not exceed the remaining image length.

INPUT_DATA carries the same CRC-32 variant used by LOAD, calculated over the
counted data bytes only. Count 0 signals end-of-stream and has CRC32 0.

DATA has no offset field. The loader appends each block to the bytes already
received. Use one channel that preserves packet order. Wait for each reply
before you send the next request.

The reply kind and status are bytes 12 and 13. Reply data starts at byte 14.

| Kind | Value | Status | Data |
|---|---|---|---|
| ACK | 0 | 0 | Zero; LOAD, BOOT, or a DATA packet before the last packet was accepted |
| OUTPUT | 1 | Byte count, 1–16 | The specified number of callback bytes |
| RESULT | 2 | 0, or IO_ERROR (5) | Program return value `u32` at 14; remaining bytes zero |
| READY | 3 | 0 | Zero; the complete image passed the CRC check and is available |
| ERROR | 4 | Error code below | Zero |
| INPUT | 5 | Capacity, 1–16 | Zero; the program is waiting for input |

| Error code | Value | Meaning |
|---|---|---|
| UNAVAILABLE | 1 | RUN has no available program |
| BAD_REQUEST | 2 | Invalid LOAD fields, DATA count, or command in the command loop |
| BAD_CRC | 3 | The CRC of the uploaded image does not match the supplied CRC |
| ABORTED | 4 | Receive, protocol, or transport failure; the loader now accepts only CONTINUE |
| IO_ERROR | 5 | Callback transmission or acknowledgment failed; RESULT reports this error if the program returns |
| BAD_TARGET | 6 | BOOT names an address or vector table that the loader does not accept |

The image uses reflected CRC-32/ISO-HDLC:

- Polynomial: `0xEDB88320`
- Initial state: `0xFFFFFFFF`
- Final XOR: `0xFFFFFFFF`
- Python equivalent: `zlib.crc32(image)`

The CRC covers exactly `length` uploaded bytes, including program padding.
It excludes request headers and unused packet bytes.

Every LOAD first makes the previous program unavailable. This also occurs if
the loader rejects the new LOAD fields. A successful exchange has this sequence:

```text
LOAD                 → ACK
DATA (not last)       → ACK       [repeat as necessary]
DATA (last)           → READY     [after the image CRC check]
RUN                  → OUTPUT, INPUT, or RESULT
OUTPUT_ACK           → OUTPUT, INPUT, or RESULT
INPUT_DATA           → OUTPUT, INPUT, or RESULT  [until RESULT]
CONTINUE (CONT)       → RLSD
```

RUN makes the program unavailable before it calls the entry point.
Upload the complete program again before another execution. The last DATA
packet produces READY without an additional ACK. A nonzero program return
value is application data. It is not a protocol error if RESULT status is zero.
OUTPUT_ACK or INPUT_DATA outside its callback exchange produces BAD_REQUEST.

After BAD_REQUEST, BAD_CRC, BAD_TARGET, or UNAVAILABLE, the loader can still accept commands.
However, the reference host marks the session as failed after any ERROR reply.
After a timeout, invalid reply, unexpected reply, or disconnection, stop loader
commands. Do not retry a request or reconnect to continue the session.
Do not repeat RUN, OUTPUT_ACK, or INPUT_DATA. The protocol cannot detect duplicate requests.
If the RUN result is unknown, the program may already have run.
Send CONTINUE to release boot. Before another attempt, start a new boot and
claim it again.

## One-boot alternate image

BOOT selects the vector table that the stock bootloader hands off to when
it finishes this boot. Without a selection it uses the stock main application
at `0x00438000`. The stock updater, its error handling, and its teardown run
unchanged. Only the address passed to the stock handoff routine changes. That
routine sets VTOR, loads MSP from the table, and branches to the reset vector.

The loader accepts a target only if all of these conditions hold:

- The address is a multiple of 4 KiB in one of these regions:
  - MRAM `[0x00438000, 0x007FE000)`;
  - ITCM `[0x00001000, 0x00040000)`.
- The initial stack pointer is a multiple of 8 in `(0x20000000, 0x20400000]`.
- The reset vector has the Thumb bit set. Its address is at least the table
  address plus 8, and below the end of the same region.

The first ITCM page is excluded because the stock bootloader copies code to
`0x00000040–0x0000006C` at startup and calls it until the handoff. No other stock
code literal points into ITCM, and the bootloader does not configure the MPU.

Otherwise BOOT replies BAD_TARGET. Each BOOT first clears any earlier selection,
so a rejected BOOT leaves none. Address 0 only clears it, and the last accepted
BOOT wins. Earlier bootloader builds reply BAD_REQUEST to BOOT.

The selection takes effect only through CONTINUE in the command loop. In each of
these cases, the loader discards it and boot continues to the stock application:

- the BOOT ACK cannot be transmitted;
- any later abort or callback IO_ERROR.

After the session, the manager discards the selection if the stock OTA flag is
pending (`0x55555555` at `0x007FE000`). The updater may overwrite any part of the
main-application region. Otherwise, the manager stores the selection in DTCM
at `0x2007CFF0`, as three words: a marker, the address, and its complement.
That address is just below the stock bootloader's MSP limit. The stock
bootloader's static RAM ends at `0x200271C8`, and none of its code literals
point into the gap. The manager clears the record at the start of every boot,
before it checks for UART2 availability.

Both stock handoff call sites (`0x0042E3D4` after an update, `0x0042E440` on a
normal boot) call the patch instead. The patch reads and clears the record, then
checks the target again with the rules above. If the record is valid and the
target still passes, it hands off to the target. Otherwise it hands off to
`0x00438000`. A reset of the temple therefore starts the stock application
unless a new session selects the target again.

The stock DFU task checks bit 29 of the stock application's initial stack
pointer before it calls the handoff. A selection does not bypass that check.

The record has a fixed marker and no secret, because the loader has no random
number generator. Code that writes this DTCM slot between the boot-entry clear
and the handoff can forge a selection. Code that runs in that window can already
take control of the boot, so this adds no new access. The handoff still applies
the target checks above, so a forged record can only start an image that passes
them in the main-application MRAM region or in ITCM. A selection from an earlier boot
cannot persist, because every boot clears the record before it reaches the
handoff. MSP overflow cannot reach the slot: the stock MSP limit `0x2007D000`
faults first. A memory-corruption bug in the stock bootloader or this patch
during that window could still forge a selection.

The host cannot confirm the outcome from RLSD. If a BOOT reply is lost, the
loader may have accepted it. Treat the selection as unknown and check which
application starts.

[altboot.py](tools/altboot.py) reads the OTA flag and the target vectors with
`dump.bin`, sends BOOT, and releases boot. It releases boot even after a failure.
`recover.py --address ADDRESS --boot` writes and verifies a raw image, then
selects it in the same session.

`altboot.py ADDRESS --load IMAGE` with an ITCM address does not change MRAM.
It performs these steps in one session:

1. It checks RAM API version 2 and the OTA flag.
2. It uploads [ramload.c](src/examples/ramload.c) once and streams the image,
   padded to 16 bytes, into ITCM through `recv`.
3. It checks the CRC of the loaded range with `checksum.bin`, then sends BOOT.

It releases boot after a failure too; nothing persistent has changed. The
loader accepts `[0x1000, 0x40000)` with a 16-byte-aligned address and length. It
reports progress the same way as the MRAM writer. Power loss clears ITCM. A
warm reset can leave the contents in place, but the next boot does not select
them.

## Execution ABI

Use Thumb position-independent code. The program must return normally.

```c
typedef struct {
    uint32_t version;  /* 2 */
    int (*send)(void *context, const void *data, uint32_t size);
    void *context;
    int (*recv)(void *context, void *data, uint32_t size);
} ram_api;

uint32_t entry(const ram_api *api, uint32_t arg0, uint32_t arg1);
/* send(api->context, bytes, count): 0 success, -1 failure */
```

API version 2 appends `recv` after the version-1 fields. Programs using only
that prefix can still run. A program that needs `recv` must check `version >= 2`
before accessing it.

`recv` requests one chunk with capacity `min(size, 16)`, then waits for
INPUT_DATA. It returns the number of bytes copied, 0 for end-of-stream, or -1
on failure. A zero-size call returns 0 without a packet. The count must not
exceed the advertised capacity, and the data CRC32 must match before any bytes
are copied. A receive failure latches the same IO_ERROR state as a send failure.

`boot.py --input FILE` supplies file bytes to `recv`. Without an input file,
the host responds with end-of-stream. Python callers can pass a
`source(capacity) -> bytes` callable to `Client.execute`. Programs can alternate
input and output; each callback still uses one request/reply exchange at a time.

The program runs synchronously in the protocol worker, on its 4 KiB stack.
About 2.9 KiB remain at program entry, measured in emulation with the build in
this tree. The RTOS stack limit (PSPLIM) faults a deeper program instead of
letting it write past the stack. The `send` callback
splits data into OUTPUT replies with a maximum of 16 bytes each. It waits for
OUTPUT_ACK after each reply. If no previous send failed, a zero-size send
succeeds without a packet.

After the first send failure, all further sends return -1. If the program
returns, the loader reports RESULT with status IO_ERROR. It then accepts only
CONTINUE.

The API and context are valid only for the current call to the program.
Keep output data valid until `send` returns. Do not retain the API or context
pointers. Do not schedule asynchronous callback calls. Do not leave tasks
that execute code from the upload buffer. See [ram_api.h](src/ram_api.h) and the
[callback example](src/examples/echo.c).

The trampoline saves and restores these registers around the call:

- r0–r12 and LR
- APSR flags, PRIMASK, BASEPRI, FAULTMASK, and CONTROL
- FPSCR, VPR, and s0–s31
- PSPLIM and MSPLIM

The program must keep a valid stack and return context. The trampoline does
not isolate the program. It does not reverse changes to RAM, peripherals,
interrupt-controller state, or tasks. Other effects of privileged code also
remain.

On first use with inactive FP context (`CONTROL.FPCA=0`), VMRS can initialize
FPSCR from FPDSCR. The trampoline restores the context saved after that
initialization. Before execution, the loader cleans the uploaded data-cache
lines and invalidates the instruction cache.

## Time limits

The normal command wait has no timeout. After a frame starts, reception fails
if no new byte arrives for 128 ticks (125 ms). Each DATA, INPUT_DATA, or OUTPUT_ACK wait has
an overall timeout of 2048 ticks (2 s).

Each temple transmission uses a local polling timeout of 21 ticks
(approximately 20.5 ms). Loader replies, OKAY, and RLSD also have a 6-tick delay
before transmission to allow the direction to change.

These time limits require the scheduler and tick counter to continue to run.
While held, the higher-priority manager feeds the nPM1300 watchdog immediately,
then every 5120 ticks (5 s), retrying a failed/busy-bus feed after 1024 ticks.
The bounded IOM7 operation restores its temporary power and interrupt state and
writes only WATCHDOGKICK, preserving the configured watchdog deadline. Before
each kick it reads TIMERCONFIG and the target bytes, accepting only the measured
watchdog-reset / 2 ms / 0x003c00 profile (30.72 s). Status and reserved bytes are
not configuration. An unexpected profile is not fed or reconfigured. It
requires the observed stock pin/bus state; it does not take over an active bus.
After deleting a claimed session's worker, the manager makes one final bounded,
best-effort kick, including sessions released before its first checkpoint. A
successful kick gives the following boot path a fresh period; failure does not
block release. The launched application owns subsequent watchdog service.

Interrupts are masked during the temporary IOM7 ownership. All power/bus polls
share a 250,000-CPU-cycle DWT deadline and a 32,768-poll fallback if CYCCNT is
unavailable or frozen. The cycle limit is about 2.60 ms at 96 MHz or 1 ms at
250 MHz, plus setup/cleanup overhead; the fallback is an iteration bound, not
a measured silicon time guarantee. Debug-enable state is restored and CYCCNT
is never reset. A timeout can cause UART data loss and a session abort. An
aborted write can leave a partially written destination; no rollback is implied.

The case independently feeds its stock PB2 watchdog on the first complete host
packet, then at most once per 5 s of hardware TIM2 time, even during packet
bursts. TIM2 must be unused/clock-gated on entry; the relay resets/gates it on
exit. Pulses run between packets only, and receive waits remain bounded.
The interval assumes the pinned stock 64 MHz timer clock; no interrupt-driven
software tick is used while the case masks interrupts.

The case does not feed while awaiting host bytes or a temple reply. An idle
host, incomplete packet, or long-running program producing no replies can
exhaust the relay's bounded polling wait and exit; the case watchdog is also
not protected during that silence. Thus an unlimited temple hold does not
imply an unlimited case relay wait. Programs using this transport must return
or exchange callback frames within the relay's receive bound. These loop-count
bounds are not specified in wall-clock seconds. Supporting arbitrary pauses
needs a nonblocking pulse mechanism, not a blocking pulse inside UART reception.

There is no execution timeout. A nonreturning program that allows the manager
to run can keep the temple alive; masked interrupts, persistent PMIC-bus
ownership or scheduler failure can prevent feeding and cause reset. Recovery
from arbitrary faulty code is not guaranteed.

## Uploaded MRAM recovery writer

[recover.py](tools/recover.py) uses LOAD and RUN to upload
[recover.c](src/examples/recover.c). The writer requires RAM API version 2.
`arg0` is the MRAM destination and `arg1` is the byte count; both must be
multiples of 16. A zero-length call checks API support without programming.
The host performs this check before backing up or writing the target range.

The writer stays resident while `recv` supplies framed input chunks. It fills
a 256-byte RAM buffer, programs and compares that block, then reports a
little-endian cumulative byte count through `send`. Early EOF or any callback
failure stops programming. Raw mode uploads the writer once for the entire
range. Application mode streams the body in one invocation and uses a separate
short invocation for the vector commit after checking the body CRC.

The writer accepts physical MRAM addresses in `[0x00400000, 0x00800000)`.
An active stock OTA flag does not block programming. It calls the stock 2.3.2.14 MRAM routine
at Thumb address `0x0042E83D` with the programming key, source, destination,
and word count. The host checks the stock bootloader SHA-256 before using this
binding, with the known hooks restored in its copy of the bytes.

The stock routine saves interrupt state, enables ROM access, calls the ROM
programming service, cleans up, and restores interrupt state. The uploaded
writer invalidates the programmed destination's CPU data-cache lines, then
compares the destination with the source before reporting progress. Return 0
means success; 1 means invalid bounds/alignment; 3 means a readback mismatch;
4 means RAM API version 2 is required; and 5 means incomplete input or callback
failure. Stock programming errors are returned unchanged.

The host backs up the affected range and checks its CRC before writing. It
writes the application body first, checks its CRC, then writes the first 16
vector-table bytes and checks the full CRC. It preserves alignment padding
from the backup. Only successful verification permits CONTINUE. Neither this
ordering nor the backup makes the update atomic. A failed or interrupted write
can leave an incomplete main application. In default application mode, writes
remain within `[0x00438000, 0x007FE000)`.

With `--address`, the same tool writes raw bytes to the selected MRAM address.
Writes whose aligned range extends outside `[0x00438000, 0x007FE000)`
require `--i-verified-the-addresses`. This mode preserves
neighboring bytes in the first and last 16-byte units and writes in address
order, without vector-table checks. It can write the pending OTA flag,
bootloader, or settings. Overwriting resident services used by the current
session can stop it before verification or CONTINUE. Hardware programming
permissions still apply. `--hold`
omits CONTINUE after successful verification; an uncleared pending OTA flag
can cause the stock updater to run when boot is released.

Tests execute the writer and the pinned stock MRAM wrapper with modeled ROM
programming and power controls. Right-temple hardware tests also cover streamed
input, input CRC rejection, and programming, readback, and restoration of an
unused 1 KiB MRAM range. Full application replacement is not hardware-tested.

## Optional case USB relay

The case relay puts each temple packet inside a separate packet.
[boot.py](tools/boot.py) uses [link.py](tools/g2patch/link.py) to load
[case_reset_loader.c](src/case/case_reset_loader.c) into RAM. One case program
performs the reset, claim, and relay operations. Case flash does not change.

After the bridge setup in `link.py`, the case sends this startup data:

```text
16 bytes: four little-endian UART register values
11 bytes: "G2U2_ARMED\n"
21 bytes: HELO beacon
12 bytes: "G2RAM_READY\n"
```

The case resets the temple and forwards HELO. Wait for G2RAM_READY, validate
HELO, and compute HOLD on the host. Allow 30 ms after HELO for the temple to
switch to receive mode. Send HOLD through G2TX and verify the returned OKAY
on the host. Complete this exchange within the temple's 500 ms boot window.

| Direction | Packet |
|---|---|
| Host → case | `G2TX`, length `u8`, temple packet[length], checksum `u8` |
| Case → host | `G2RX`, status `u8`, length `u8`, temple packet[length], checksum `u8` |
| Host → case | `G2EX` (four bytes, no checksum; exits the relay) |

Each outer checksum is the sum of all preceding bytes in that packet,
modulo 256. G2TX length is 9, 25, or 32. Use length 0 to receive without a
transmission to the temple. G2RX length is 13, 21, 29, or 32 after a successful receive.
Otherwise, it is 0.

| Relay status | Meaning |
|---|---|
| 0 | Transport success |
| 1 | The case did not transmit all bytes to the temple |
| 2 | Receive failure |

Status 0 does not confirm the inner checksum or packet contents. The host must
check the temple packet. An invalid host packet format or checksum stops the
relay without a G2RX error packet. Each G2TX produces a maximum of one G2RX.
The callback waits for OUTPUT_ACK before it sends more output.

G2EX does not send CONTINUE. Release the temple before you stop the relay.
Keep the same case program running throughout the exchange. A case reset or
ROM transition to load a different bridge can lose the held temple session.
