use core::panic;
use std::collections::HashMap;
use std::mem::size_of;
use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::process::{Child, Command};
use std::os::unix::process::CommandExt;

use crate::dwarf_data::DwarfData;

pub enum Status {
    /// Indicates inferior stopped. Contains the signal that stopped the process, as well as the
    /// current instruction pointer that it is stopped at.
    Stopped(signal::Signal, usize),

    /// Indicates inferior exited normally. Contains the exit status code.
    Exited(i32),

    /// Indicates the inferior exited due to a signal. Contains the signal that killed the
    /// process.
    Signaled(signal::Signal),
}

/// This function calls ptrace with PTRACE_TRACEME to enable debugging on a process. You should use
/// pre_exec with Command to call this in the child process.
fn child_traceme() -> Result<(), std::io::Error> {
    ptrace::traceme().or(Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ptrace TRACEME failed",
    )))
}

fn align_addr_to_word(addr: u64) -> u64 {
    // proj-doc provided code
    addr & (-(size_of::<u64>() as i64) as u64)
}

pub struct Inferior {
    child: Child,
}

impl Inferior {
    /// Attempts to start a new inferior process. Returns Some(Inferior) if successful, or None if
    /// an error is encountered.
    pub fn new(target: &str, args: &Vec<String>, breakpoints: &mut HashMap<u64, Option<u8>>) -> Option<Inferior> {
        println!(
            "Running target={}, args={:?}",
            target, args
        );

        let mut cmd = Command::new(target);
        cmd.args(args);

        // this unsafe block warns the multithread danger in pre_exec. 
        unsafe { cmd.pre_exec(child_traceme); } 

        let mut child = Inferior {
            child: cmd.spawn().ok()? // if Result is Err, returun None
        };

        // Block waiting for the child process being stopped by the OS.
        // We don't need to provide WUNTRACED because the child is traced in advance.
        match child.wait(None).ok()? {
            Status::Stopped(signal::Signal::SIGTRAP, _) => {
                // set all breakpoints now
                for (addr, orig) in breakpoints {
                    if let Ok(x) = child.set_breakpoint(*addr) {
                        *orig = Some(x);
                    } else {
                        // set breakpoint failure.
                        child.try_kill_and_reap();
                        return None;
                    }
                }
                Some(child)
            }
            _ => None,
        }
    }
    
    // /// Now we are locating 
    // pub fn resume_and_step(&self, orig: u8) {
    //     self.re
    // }
    
    pub fn write_byte(&self, addr: u64, val: u8) -> Result<u8, nix::Error> {
        // proj-doc provided code
        let aligned_addr = align_addr_to_word(addr);
        let byte_offset = addr - aligned_addr;
        let word = ptrace::read(self.pid(), aligned_addr as ptrace::AddressType)? as u64;
        let orig_byte = (word >> 8 * byte_offset) & 0xff;
        let masked_word = word & !(0xff << 8 * byte_offset);
        let updated_word = masked_word | ((val as u64) << 8 * byte_offset);
        ptrace::write(
            self.pid(),
            aligned_addr as ptrace::AddressType,
            updated_word as *mut std::ffi::c_void,
        )?;
        Ok(orig_byte as u8)
    }

    /// Return the original byte.
    /// If it fails, it'll call try_kill_and_reap().
    pub fn set_breakpoint(&mut self, addr: u64) -> nix::Result<u8> {
        match self.write_byte(addr, 0xcc) {
            Ok(x) => Ok(x),
            Err(err) => {
                self.try_kill_and_reap();
                Err(err)
            }
        }
    }
    
    pub fn print_backtrace(&self, debug_info: &DwarfData) -> nix::Result<()> {
        let regs = ptrace::getregs(self.pid())?;
        let mut rip = regs.rip as usize;
        let mut rbp = regs.rbp as usize;

        // x86 conventions:
        // rbp is the frame start address, and the value at address %rbp is the previous rbp.
        // the return address is located exactly above rbp.

        loop {
            let line = debug_info.get_line_from_addr(rip).unwrap_or_default();
            let func = debug_info.get_function_from_addr(rip).unwrap_or("??".to_string());
            println!("{}, {}:{}", func, line.file, line.number);

            if func == "main" {
                break
            }

            rip = ptrace::read(self.pid(), (rbp + 8) as ptrace::AddressType)? as usize;
            rbp = ptrace::read(self.pid(), (rbp) as ptrace::AddressType)? as usize;
        }
        // TODO: doesn't work for the sleep_print sample. Why?

        Ok(())
    }

    /// Wake up the inferior and run it until it stops or terminates.\
    /// Returns a Status to indicate the state of the process after the call.\
    /// If the process didn't exit, return the ownership.\
    /// opt_infer must be a Some, but it might become None after cont().
    pub fn cont(opt_infer: &mut Option<Inferior>) -> Status {
        if let Some(infer) = opt_infer {
            if ptrace::cont(infer.pid(), None).is_err() {
                // The project doc says panicking directly is okay.
                infer.try_kill_and_reap(); // try to kill it to prevent it outlive the debugger
                panic!("Error continuing inferior");
            }
            match infer.wait(None) {
                // The project doc says panicking directly is okay.
                Err(_) => {
                    infer.try_kill_and_reap(); // try to kill it to prevent it outlive the debugger
                    panic!("Error continuing inferior");
                },
                Ok(status) => {
                    match status {
                        Status::Exited(_) | Status::Signaled(_) => {
                            // the subprocess is reaped now.
                            opt_infer.take();
                        }
                        Status::Stopped(_, _) => (),
                    }
                    status
                }
            }
        } else {
            // blame the programmer
            panic!("continue on a None Option<Inferior>");
        }
    }

    /// Returns the pid of this inferior.
    pub fn pid(&self) -> Pid {
        nix::unistd::Pid::from_raw(self.child.id() as i32)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<Status, nix::Error> {
        Ok(match waitpid(self.pid(), options)? {
            WaitStatus::Exited(_pid, exit_code) => Status::Exited(exit_code),
            WaitStatus::Signaled(_pid, signal, _core_dumped) => Status::Signaled(signal),
            WaitStatus::Stopped(_pid, signal) => {
                let regs = ptrace::getregs(self.pid())?;
                Status::Stopped(signal, regs.rip as usize)
            }
            other => panic!("waitpid returned unexpected status: {:?}", other),
        })
    }

    /// Try to kill and reap the child, ignoring any error.
    pub fn try_kill_and_reap(&mut self) {
        unsafe {
            self.child.kill().unwrap_unchecked();
            self.child.wait().unwrap_unchecked();
        }
    }
}
