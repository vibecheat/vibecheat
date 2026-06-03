# VibeCheat: Linux Process Memory Scanner and Editor

VibeCheat is a memory scanning and editing tool for Linux (tested on Arch Linux) written in Rust. It functions similarly to Cheat Engine, allowing you to search for, filter, and edit variables inside a target process's memory space using a high-fidelity Web Dashboard.

## Features
1. **Target Selection:** Search and attach to target processes directly from the sidebar.
2. **Multiple Data Types:** Supports scanning and writing `i8`, `i16`, `i32`, `i64`, `f32`, and `f64`.
3. **Custom Alignment:** Toggle 1, 2, 4, or 8-byte alignments. Highly useful for emulator memory structures.
4. **Interactive Filters:** Perform *Exact* or *Unknown Initial Value* scans, then filter candidates using *Increased*, *Decreased*, *Changed*, or *Unchanged* comparison options.
5. **Low Overhead Scanning:** Memory is chunked in 16MB blocks to minimize context-switches and prevent application halts.

---

## Configuration & Requirements (Permissions)

Under modern Linux distributions, memory scanner access is restricted by the **Yama security module**.
To check your system's current ptrace restriction level:
```bash
cat /proc/sys/kernel/yama/ptrace_scope
```

If it outputs `1`, you must run the server binary with `sudo` (root privileges) to read and write arbitrary process memory.

### Compile and Start VibeCheat Server
1. Compile the server:
   ```bash
   cargo build --release
   ```
2. Launch the server (with `sudo` if ptrace is restricted):
   ```bash
   sudo ./target/release/vibecheat
   ```
   *The server will start listening on `http://localhost:5000`.*

---

## Step-by-Step Dashboard Guide

### 1. Launch the game
Launch your target game (e.g. *Castlevania Advance Collection* or the included `target_app`).

### 2. Access the Dashboard
Open your web browser and navigate to:
```url
http://localhost:5000
```

### 3. Connect to the Process
1. Locate your game process in the **sidebar** (or filter it using the search box) and click on it.
2. Under **Scan Config**, select the desired **Data Type** and **Memory Alignment** (Choose *1-Byte Alignment* for emulators).
3. Click **Attach and Set Configuration**.

### 4. Locate and Edit Values
1. Set the initial search value (e.g. current HP or Gold) and click **First Scan**.
2. Cause the value to change in the game (e.g. spend gold, take damage).
3. Under **Memory Scanner**, select **Next Scan (Filter candidates)**, input the new value, and select **Next Scan**.
4. Repeat if necessary until the matches in the **Candidates List** narrow down.
5. Click **Edit** next to the address in the candidates list, enter your new value, and click **Write Memory** to update it instantly!

