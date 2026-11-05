# G2 bootloader patch

This project is intended for those who work on or experiment with custom
firmware for Even Realities G2 smart glasses.

It patches the bootloader, allowing a connected computer to stop an Even G2
temple during boot, upload a small RAM program through UART2, run it, and
resume booting. The host tools use the charging case as a USB-to-UART relay.
The case program runs in RAM; case flash does not change.

Only the stock **2.3.2.14 bootloader** is supported. The patch tool checks its
SHA-256 before it changes any bytes. The case relay requires **case 1.2.57**.

The current patch passed emulator tests and hardware tests on both temples
with **hardware 5** and **main application 2.4.0.24**.

## Introduction

Even Realities G2 smart glasses are an excellent piece of hardware, and their
firmware is not locked away from consumer modification. While their software
is notable, there are some people (like yours truly) whose needs it doesn't
meet, and who would wish to develop their own firmware for the glasses.

Unfortunately, there's a risk involved: firmware updates are performed by the
main firmware itself, so buggy custom firmware may leave the glasses unable to
boot or accept normal firmware updates. Recovery may require complicated and
dangerous disassembly to access the microcontroller.

The G2 glasses use an Ambiq Apollo510B system-on-chip. Their boot process
works like this:

1. First, the Apollo ROM code runs, initializes the essential hardware and
   passes control to Apollo Secure Boot Loader (SBL).

2. Apollo SBL reads configuration burnt into the chip and acts accordingly.
   This configuration, among many things, controls whether UART modules are
   initialized, allowing debug and firmware update access; and whether OEM
   firmware is cryptographically validated.

   To their credit, Even Realities have not enabled firmware cryptographic
   protections, but, regrettably, they have not enabled any debugging and
   firmware-updating facilities on the pogo pins - the only user-accessible
   connections to the glasses.

3. SBL passes control to the Even bootloader. This is Even Realities-provided
   software that takes care of additional hardware initialization and stored
   firmware updates. If a firmware update is stored in the NOR flash filesystem
   and its pending-update flag is set, it flashes that version.

   However, the bootloader has no means to receive anything from the user.
   The only user-accessible UART2 is effectively inert.

4. The Even bootloader passes control to the main application. This is the
   application that does everything the glasses normally do, running the display,
   Bluetooth, and UART2 on the pogo pins. This application allows connected
   devices to write new firmware for the Even bootloader to copy over using
   commands over BLE or UART2. Thus, if the application is defunct for any reason,
   it's not possible to recover it with a firmware update.

This project adds a UART2 RAM loader to the Even bootloader. The host uses the
charging case as a USB-to-UART relay to reset a temple, stop boot, and upload and
run a small program in RAM. This provides a path for diagnostics and recovery
without a working main application.

## Build and patch

This project uses Nix for environment management. To activate a devshell,
run `nix develop` or use your preferred method like direnv. You don't have
to use Nix and can provide necessary dependencies (LLVM, GNU Make, Python,
and some more - check `flake.nix` for the full list) by whatever means
you prefer.

With all the dependencies in place, run these commands from this directory:

```sh
make
make test
make patch FIRMWARE=/path/to/vanilla.bin
```

`make` downloads an official firmware bundle, checks its pinned SHA-256, and
extracts the case code needed for the RAM relay. Downloads and build files stay
in the ignored `build/` directory. To use a local raw case image instead, run
`make CASE_FIRMWARE=/path/to/firmware_box.raw.bin`.

The patch input can be a stock bootloader image, a supported MRAM dump, or an
EVENOTA bundle with the stock bootloader. The output is `build/bootloader.bin`,
with a hash receipt in `build/bootloader.json`. The input file does not change.

## Install through BLE

Although this patch is intended to improve recovery, flashing a bootloader is
an inherently risky operation that *MAY IRREPAIRABLY BRICK YOUR GLASSES*.

I tested it at my own risk on my own hardware, but
explicitly waive all responsibility for any possible outcomes. The purpose
of this project is to empower you, the end user (who is likely either
an enthusiast firmware developer or someone who wishes to experiment with
alternative software) with a mechanism to recover your glasses from a faulty
programming. However, there is no guarantee that this project won't ruin
your glasses instead. Read through the code (which is, fortunately, small),
or ask an AI to do it for you. Be sure you understand the benefits and risks.
Then make your own decisions.

Most certainly, if anything goes wrong, this is *NOT* a warranty-eligible event.
I would not go as far as saying that flashing non-OEM firmware revokes all
warranties, but please be very aware that if you brick your glasses with this
tool, don't ask Even to help you with it. Install this only if you're either
ready to write off the costs of failure and loss of smart glasses functionality,
or ready to open up the temple and try flashing back with JTAG, hoping it's
accessible. In the latter case, I wish you the best of luck.

All this said, if you decide to proceed:

Connect the case to the computer by USB and put the glasses in. Ensure both temples
are seated (the Even app may help with this). The connection can get flaky
if there's dirt on the contacts or if you have adjusted the fit by
bending the arms. Put the case away where you won't accidentally shake it.
Close other glasses clients on the computer and turn Bluetooth off on your phone.
Keep the computer's Bluetooth on for installation.

Replace `$TEMPLE_ADDRESS` with the right temple's BLE address or UUID, and
`$CASE_PORT` with the case serial port:

```sh
python3 tools/flash.py build/bootloader.bin \
  --address "$TEMPLE_ADDRESS" --side right --verify-port "$CASE_PORT"
```

The tool writes the bootloader using the stock OTA mechanism.
After that, it resets the temple and uses the newly installed bootloader
to read back the installed image CRC twice to verify the write.

Check that the main application starts before you install on the other temple.
Use `--side left` and the left temple's address for the other temple.

## Run a RAM program

With the patched bootloader installed on the selected temple, you can interrupt
the boot process and run your prebuilt code on the glasses. You write a
function that conforms to the following API:

```c
uint32_t entry(const ram_api *api, uint32_t arg0, uint32_t arg1);
```

Here, `api` provides a callback for sending data back, and `arg0` and
`arg1` are two arbitrary 32-bit values of your choice, so you don't have to recompile
diagnostic programs every time. There is an echo program included in `src/examples/echo.c`
that sends back little-endian `0x21594548` ("HEY!"), followed by the two arguments.
To run it, with both temples well-seated in the USB-connected case:

```sh
python3 tools/boot.py build/echo.bin --port "$CASE_PORT" --side right \
  --arg0 6 --arg1 7
```

The tool resets and interrupts boot for the selected temple, runs the program,
then sends CONTINUE to release boot. Audit files and callback output go in `build/runs/`.

Two other examples take a start address in `--arg0` and a byte count in `--arg1`:
`checksum.bin` returns the CRC-32 of that memory range, and `dump.bin` sends its
contents to the host, saved as `callback.bin` in the run directory. The entire
range must be readable; neither program catches memory-access faults.

Programs must be position-independent Thumb code, 2–512 bytes long, and return
normally. They run synchronously with privileged access and no isolation or
execution timeout. CONTINUE cannot interrupt a program. Recovery from a faulty
program is not guaranteed. See [PROTOCOL.md](PROTOCOL.md) for the ABI, packet
format, and failure handling.

## Security

Bootloader access is secured with a HMAC-SHA256 challenge-response mechanism,
against a pre-shared secret embedded in the bootloader. By default, this secret
is a "DEFAULTNOTSECRET" ASCII string. You may override it if you want to restrict
access and add additional protection against "evil maid"-type attacks.

An important caveat is that the current bootloader code does not use an RNG, so the
challenges will be reused heavily. This is unlikely to matter in practice,
as the handshake is done over a wired connection right to your computer.
Yet, be aware that the challenge-response mechanism is weaker than it could've
been, and merely avoids sending a secret in plain, but is not sufficient to
reasonably protect against replay attacks. If you would like to improve this,
your help would be most appreciated.

## Contribution, licensing and credits

This project is Free Software. You're free to use it for any purpose,
free (and encouraged) to study how it works, free to redistribute and make copies
of it, and free (and even more encouraged!) to release any improvements to it.

If you have an improvement you'd like to share, please send it to me.
The only asks I have are that you write the accompanying introductory notes
yourself (feel free to use an LLM for any proofreading and advice, but
not to replace your own thoughts and voice please), in your own words; and
that you have tested your changes on real hardware. That is, if there's
something that goes onto the glasses, of course. If you find those requirements
excessively onerous, please consider forking the project instead.

This project is distributed under the [MIT license](LICENSE). Glasses firmware
is the property of Even Realities and is not covered by it. This project does
not redistribute any substantial portions of Even Realities code.

This project would not be possible without these awesome projects, from which
I borrowed information (and a bit of source code, where licensing allowed me to):

- Kalani Helekunihi's [Even Realities WebFlasher] for case interaction protocol and
  [openCFW] for the wealth of knowledge and research into the G2 firmware.

- James Babcock's [g2flash] for BLE protocol details and Faceclaw patches.

- [BearSSL] project for HMAC and SHA256 implementations.

Last but not least, a special thank you to Even Realities for the G2s.


[Even Realities WebFlasher]: https://github.com/AM-Guru/evenRealities-webflasher
[openCFW]: https://github.com/kalanihelekunihi/evenRealities-openCFW-Research
[g2flash]: https://github.com/jimrandomh/g2flash
[BearSSL]: https://www.bearssl.org/
