use core::panic;
use std::collections::HashMap;

use crate::debugger_command::DebuggerCommand;
use crate::inferior::{Inferior, self};
use nix::sys::ptrace;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use crate::dwarf_data::{DwarfData, Error as DwarfError};

pub struct Debugger {
    target: String,
    history_path: String,
    readline: Editor<()>,
    inferior: Option<Inferior>, // If Some(...), the subprocess is still alive.
    debug_data: DwarfData,
    breakpoints: HashMap<u64, Option<u8>> // Option is None before the breakpoint is actually set.
}

impl Debugger {
    /// Initializes the debugger.
    pub fn new(target: &str) -> Debugger {
        let history_path = format!("{}/.deet_history", std::env::var("HOME").unwrap());
        let mut readline = Editor::<()>::new();
        // Attempt to load history from ~/.deet_history if it exists
        let _ = readline.load_history(&history_path);

        Debugger {
            target: target.to_string(),
            history_path,
            readline,
            inferior: None,


            // proj doc provided code
            debug_data: match DwarfData::from_file(target) {
                Ok(val) => {
                    val.print();
                    val
                },
                Err(DwarfError::ErrorOpeningFile) => {
                    println!("Could not open file {}", target);
                    std::process::exit(1);
                }
                Err(DwarfError::DwarfFormatError(err)) => {
                    println!("Could not load debugging symbols from {}: {:?}", target, err);
                    std::process::exit(1);
                }
            },

            breakpoints: Default::default()
        }
    }

    /// Continue the inferior.\
    /// The inferior must be a Some, otherwise it'll panic\
    /// Return the exit status msg.
    fn advance_inferior(&mut self) -> nix::Result<String> {
        let infer = match &mut self.inferior {
            Some(infer) => infer,
            None => panic!("No inferior to make progress!")
        };

        let mut regs = ptrace::getregs(infer.pid())?;
    
        // check if now we are stopping at a breakpoint
        if let Some(opt) = self.breakpoints.get(&(regs.rip - 1)) {
            let bp_addr = regs.rip - 1;

            match opt {
                None => {
                    // this case shouldn't happen, just an assertion for debug
                    infer.try_kill_and_reap();
                    panic!("Stop at a breakpoint with unknown origin byte value");
                }
                Some(orig) => {
                    // we want to stop at the next instruction and restore the breakpoint
                    // so that we can continue the process normally


                    // replace 0xcc with the origin value
                    infer.write_byte(regs.rip - 1, *orig)?;
                    
                    // restore the rip
                    regs.rip -= 1;
                    ptrace::setregs(infer.pid(), regs)?;

                    // execute the origin instruction
                    ptrace::step(infer.pid(), None)?;
                    infer.wait(None)?;

                    // restore the breakpoint
                    infer.set_breakpoint(bp_addr)?;
                }
            }
        }
        
        match Inferior::cont(&mut self.inferior) {
            inferior::Status::Stopped(sig, curr_addr) => {
                let msg = format!("Child stopped (signal {sig})");
                let loc = self.debug_data.get_line_from_addr(curr_addr).unwrap_or_default();

                Ok(format!("{}\nStopped at {}:{}", msg, loc.file, loc.number))
            },
            inferior::Status::Exited(ret_val) => {
                Ok(format!("Child exited (status {ret_val})"))
            },
            inferior::Status::Signaled(_) => 
                Ok(format!("Child is signaled and exited"))
        }
    }

    /// parse hex address as "0xabcde" or "abcde"
    /// return decimal address
    fn parse_address(addr: &str) -> Option<usize> {
        let addr_without_0x = if addr.to_lowercase().starts_with("0x") {
            &addr[2..]
        } else {
            &addr
        };
        usize::from_str_radix(addr_without_0x, 16).ok()
    }

    pub fn run(&mut self) {
        loop {
            match self.get_next_command() {
                DebuggerCommand::Run(args) => {
                    
                    if let Some(mut infer) = self.inferior.take() {
                        // There is an inferior, we need to kill and reap it first.
                        println!("Killing the previous inferior.");
                        infer.try_kill_and_reap();
                    }

                    if let Some(inferior) = Inferior::new(&self.target, &args, &mut self.breakpoints) {
                        // Now the inferior is stopped by the OS. 

                        // Put the inferior into self and get a new mutable reference.
                        self.inferior = Some(inferior);
                        
                        // Continue its executing
                        match self.advance_inferior() {
                            Ok(x) => println!("{}", x),
                            Err(_) => {
                                self.inferior.as_mut().expect("").try_kill_and_reap();
                                panic!("Error advancing inferior");
                            }
                        }
                    } else {
                        println!("Error starting subprocess");
                    }
                },
                DebuggerCommand::Continue => {
                    if self.inferior.is_none() {
                        println!("No inferior for continuing");
                        continue;
                    }

                    match self.advance_inferior() {
                        Ok(x) => println!("{}", x),
                        Err(_) => {
                            self.inferior.as_mut().expect("").try_kill_and_reap();
                            panic!("Error advancing inferior");
                        }
                    }
                },
                DebuggerCommand::Backtrace => {
                    if let Some(inferior) = self.inferior.as_mut() {
                        if inferior.print_backtrace(&self.debug_data).is_err() {
                            println!("Maybe corrupted backtrace!");
                        }
                    } else {
                        println!("No inferior for backtracing");
                    }
                },
                DebuggerCommand::Breakpoint(pos) => {
                    
                    let mut sym_addr: Option<u64> = None;

                    // First we need to determine the type of pos
                    // raw address starts with "*"
                    if !pos.starts_with("*") {
                        // replace pos to the raw address

                        if let Ok(line) = pos.parse::<u64>() {
                        // it shoule be a line number

                        if let Some(addr) = 
                            self.debug_data.get_addr_for_line(None, line as usize) {
                            sym_addr = Some(addr as u64);
                        }
                        } else {
                            // it should be a function name
                            if let Some(addr) = self.debug_data.get_addr_for_function(None, pos.as_str()) {
                                sym_addr = Some(addr as u64);
                            }
                        }
                    } else {
                        sym_addr = if let Some(addr) = Self::parse_address(&pos[1..]) {
                            Some(addr as u64)
                        } else {
                            None
                        }
                    }

                    match sym_addr {
                        // Explicitly exclude cases contain " "
                        Some(addr) => {

                            // check if there is already a breakpoint.
                            if self.breakpoints.contains_key(&addr) {
                                println!("The breakpoint already exists");
                                continue; // go back to parse next cmd
                            }

                            self.breakpoints.insert(addr, 
                                
                                if let Some(inferior) = self.inferior.as_mut() {
                                    // If the inferior is running, set the breakpoint now.
                                    match inferior.set_breakpoint(addr) {
                                        Ok(x) => Some(x),
                                        Err(_) => {
                                            panic!("Setting breakpoint error");
                                        }
                                    }
                                } else {
                                    // If the inferior isn't running, give it a None
                                    None
                                }
                            );
                            println!("Set a breakpoint at {pos}");
                        },
                        None => println!("invalid breakpoint position.")
                    }
                },
                DebuggerCommand::Quit => {
                    if let Some(mut infer) = self.inferior.take() {
                        // There is an inferior, we need to kill and reap it first.
                        println!("Terminating the running inferior");
                        infer.try_kill_and_reap();
                        // We don't concern the exit status.
                    }
                    return;
                }
            }
        }
    }

    /// This function prompts the user to enter a command, and continues re-prompting until the user
    /// enters a valid command. It uses DebuggerCommand::from_tokens to do the command parsing.
    ///
    /// You don't need to read, understand, or modify this function.
    fn get_next_command(&mut self) -> DebuggerCommand {
        loop {
            // Print prompt and get next line of user input
            match self.readline.readline("(deet) ") {
                Err(ReadlineError::Interrupted) => {
                    // User pressed ctrl+c. We're going to ignore it
                    println!("Type \"quit\" to exit");
                }
                Err(ReadlineError::Eof) => {
                    // User pressed ctrl+d, which is the equivalent of "quit" for our purposes
                    return DebuggerCommand::Quit;
                }
                Err(err) => {
                    panic!("Unexpected I/O error: {:?}", err);
                }
                Ok(line) => {
                    if line.trim().len() == 0 {
                        continue;
                    }
                    self.readline.add_history_entry(line.as_str());
                    if let Err(err) = self.readline.save_history(&self.history_path) {
                        println!(
                            "Warning: failed to save history file at {}: {}",
                            self.history_path, err
                        );
                    }
                    let tokens: Vec<&str> = line.split_whitespace().collect();
                    if let Some(cmd) = DebuggerCommand::from_tokens(&tokens) {
                        return cmd;
                    } else {
                        println!("Unrecognized command.");
                    }
                }
            }
        }
    }
}
