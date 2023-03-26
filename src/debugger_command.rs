pub enum DebuggerCommand {
    Quit,
    Run(Vec<String>),
    Continue, 
    Backtrace,
    Breakpoint(String), 
}

impl DebuggerCommand {
    pub fn from_tokens(tokens: &Vec<&str>) -> Option<DebuggerCommand> {
        match tokens[0] {
            "q" | "quit" => Some(DebuggerCommand::Quit),
            "r" | "run" => {
                let args = tokens[1..].to_vec();
                Some(DebuggerCommand::Run(
                    args.iter().map(|s| s.to_string()).collect(),
                ))
            },
            "c" | "cont" | "continue" => Some(Self::Continue),
            "bt" | "back" | "backtrace" => Some(Self::Backtrace),
            "b" | "break" | "breakpoint" => Some(Self::Breakpoint(tokens[1..].concat())),
            // Default case:
            _ => None,
        }
    }
}
