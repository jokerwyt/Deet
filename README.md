# Deet
A simple gdb-like debugger for Linux and x86.
(CS110L proj-1)

# Usage
- `cargo run <program path>`
- Supported commands
    ```
        "q" | "quit" 
        "r" | "run" 
        "c" | "cont" | "continue"
        "bt" | "back" | "backtrace"
        "b" | "break" | "breakpoint"
    ```
- support different type of breakpoints:
  - Raw address: `b *0x1234`
  - Line number: `b 10`
  - Function name: `b main`


The program must compile with `-O0 -g -no-pie -fno-omit-frame-pointer`.
There are some sample C code in `samples/`, if you want to compile them, run `make` directly.
