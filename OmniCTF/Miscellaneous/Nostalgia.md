
<img width="1129" height="377" alt="image" src="https://github.com/user-attachments/assets/b582e167-b129-4133-96a1-598c0c52b57a" />

<img width="756" height="61" alt="image" src="https://github.com/user-attachments/assets/578afd09-4472-49ba-998d-e23d307fd5e2" />

---

## Challenge

We're given a file nostalgia.sb3 (a Scratch project) and the hint *"Such old memories )"*.

## Recon

A `.sb3` file is actually just a ZIP archive. Let's extract it:

```bash
unzip nostalgia.sb3 -d extracted
```

The contents are unusual for a normal Scratch project: a handful of assets (svg/png/wav) and a project.json weighing in at ~177 MB — far more than any typical Scratch project would ever need.

Inspecting the variables and lists defined on the Stage, we find names like:

- RISCV.state, RISCV.kHz
- `RISCV.ROM` — a list with ~4.26 million elements
- `RISCV.DTB` — a list with 1536 elements
- Terminal.inputBuffer / Terminal.outputBuffer

This is the classic signature of a RISC-V emulator built entirely out of Scratch blocks one that boots a Linux kernel + busybox and renders a terminal directly on the Scratch stage. In other words, the project literally "boots Linux" using nothing but Scratch scripts RISCV.ROM holds the memory image, and RISCV.DTB is a Device Tree Blob.

## Extracting the ROM

Scratch lists with 4 million elements aren't exactly readable by eye, but `project.json` is valid JSON, so we parse it with Python:

```python
import json

data = json.load(open("project.json"))
stage = data["targets"][0]

rom = stage["lists"]["BIddAr(]GI%+Rgvo%,H1"][1]   # RISCV.ROM
dtb = stage["lists"]["6UezCr/n(05{5j!8#!.#"][1]   # RISCV.DTB

rom = [x if x != "" else "0" for x in rom]  # last element was empty
dtb = [x if x != "" else "0" for x in dtb]

open("rom.bin", "wb").write(bytes(int(x) & 0xFF for x in rom))
open("dtb.bin", "wb").write(bytes(int(x) & 0xFF for x in dtb))
```

Each element of the list is a single byte (0-255) stored as a string. Running file dtb.bin confirms our hypothesis:

```
dtb.bin: Device Tree Blob version 17, size=1536, boot CPU=0, string block size=227, DT structure block size=1224
```

## Flag

There was no need to actually write or run a RISC-V emulator running strings directly on rom.bin does the job, since an initramfs contains plain, uncompressed text:

```bash
strings -n 8 rom.bin | grep -i -E "flag|OmniCTF|busybox|linux version"
```

The output confirms a full busybox initramfs (users ctf/root, /bin/login -f ctf, BusyBox v1.36.0), and among the cpio entries we find the file `root/readme.txt`:

```
...root/readme.txt
console.log("OmniCTF{ig_bro_have_some_n0stalgiaaa-676767676789}");
...run
```
