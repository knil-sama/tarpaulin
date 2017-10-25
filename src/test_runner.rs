use breakpoint::*;
use ptrace_control::*;
use tracer::TracerData;
use std::convert::From;
use std::default::Default;
use std::collections::{HashSet, HashMap};
use nix::Error as NixErr;
use nix::unistd::*;
use nix::sys::ptrace::ptrace::*;
use nix::sys::signal;
use nix::sys::wait::*;
use procinfo::pid::{stat, status, Stat, Status};
use nix::libc::pid_t;

#[derive(Eq, PartialEq, Debug)]
struct RunState {
    wait_signal: WaitStatus,
    child_stats: Option<Stat>,
    child_status: Option<Status>,
}

impl Default for RunState {
    fn default() -> Self {
        RunState {
            wait_signal: WaitStatus::StillAlive,
            child_stats: None,
            child_status: None,
        }
    }
}

impl From<WaitStatus> for RunState {
    fn from(wait: WaitStatus) -> Self {
        let pid = match wait {
            WaitStatus::Exited(p, _) => pid_t::from(p),
            WaitStatus::Signaled(p, _, _) => pid_t::from(p),
            WaitStatus::Stopped(p, _) => pid_t::from(p),
            WaitStatus::Continued(p) => pid_t::from(p),
            _ => 0,
        };
        RunState {
            child_stats: stat(pid).ok(),
            child_status: status(pid).ok(),
            wait_signal: wait
        }
    }
}


fn wait_state() -> Result<RunState, NixErr> {
    let step = waitpid(Pid::from_raw(-1), Some(__WALL))?;
    Ok(RunState::from(step))
}


fn check_parents(parents: &HashSet<Pid>, current: Pid) -> bool {
    parents.contains(&Pid::from_raw(0)) 
}


fn handle_trap(pid: Pid, 
               no_count:bool, 
               thread_count: isize,
               unwarned: &mut bool,
               mut traces: &mut Vec<TracerData>, 
               mut breakpoints: &mut HashMap<u64, Breakpoint>) -> Result<(), NixErr> {
  
    if let Ok(rip) = current_instruction_pointer(pid) {
        let rip = (rip - 1) as u64;
        if  breakpoints.contains_key(&rip) {
            let bp = &mut breakpoints.get_mut(&rip).unwrap();
            let enable = (!no_count) && (thread_count < 2);
            if !enable && *unwarned {
                println!("Code is mulithreaded, disabling hit count");
                *unwarned = false;
            }
            // Don't reenable if multithreaded as can't yet sort out segfault issue
            let updated = if let Ok(x) = bp.process(pid, enable) {
                 x
            } else {
                false
            };
            if updated {
                for mut t in traces.iter_mut()
                                   .filter(|x| x.address == Some(rip)) {
                    (*t).hits += 1;
                }
            } 
        } else {
            continue_exec(pid, None)?;
        }
    } 
    Ok(())
}


/// Starts running a test. Child must have signalled STOP or SIGNALED to show 
/// the parent it is not executing or it will be killed.
pub fn run_function(pid: Pid,
                    forward_signals: bool,
                    no_count: bool,
                    mut traces: &mut Vec<TracerData>,
                    mut breakpoints: &mut HashMap<u64, Breakpoint>) -> Result<i8, NixErr> {
    let mut res = 0i8;
    // Thread count, don't count initial thread of execution
    let mut thread_count = 0isize;
    let mut unwarned = !no_count;
    // Start the function running. 
    continue_exec(pid, None)?;
    let mut ignored_parents: HashSet<Pid> = HashSet::new();
    loop {
        let step = wait_state()?;
        match step.wait_signal {
            WaitStatus::Exited(child, sig) => {
                for (_, ref mut value) in breakpoints.iter_mut() {
                    value.thread_killed(child); 
                }
                res = sig;
                // If test executable exiting break, else continue the program
                // to launch the next test function
                if child == pid {
                    break;
                } else {
                    // The err will be no child process and means test is over.
                    let _ =continue_exec(pid, None);
                }
            },
            WaitStatus::Stopped(child, signal::SIGTRAP) => {
                if check_parents(&ignored_parents, child) {
                    continue_exec(child, Some(signal::SIGTRAP))?;
                } else {
                    handle_trap(child, no_count, thread_count, &mut unwarned, 
                                traces, breakpoints)?;
                }
            },
            WaitStatus::Stopped(child, signal::SIGSTOP) => {
                if check_parents(&ignored_parents, child) {
                    continue_exec(child, Some(signal::SIGSTOP))?;
                } else {
                    continue_exec(child, None)?;
                }
            },
            WaitStatus::Stopped(child, signal::SIGSEGV) => {
                if check_parents(&ignored_parents, child) {
                    continue_exec(child, Some(signal::SIGSEGV))?;
                } else {
                    break;
                }
            },
            WaitStatus::Stopped(child, sig) => {
                let s = if forward_signals | check_parents(&ignored_parents, child) {
                    println!("Forwarding");
                    Some(sig)
                } else {
                    None
                };
                continue_exec(child, s)?;
            },
            WaitStatus::PtraceEvent(child, signal::SIGTRAP, PTRACE_EVENT_CLONE) => {
                if check_parents(&ignored_parents, child) {
                    continue_exec(child, Some(signal::SIGTRAP))?;
                } else if get_event_data(child).is_ok() {
                    thread_count += 1;
                    continue_exec(child, None)?;
                }                 
            },
            WaitStatus::PtraceEvent(child, signal::SIGTRAP, PTRACE_EVENT_FORK) => {
                let sig = if check_parents(&ignored_parents, child) {
                    Some(signal::SIGTRAP)
                } else {
                    None
                };
                continue_exec(child, sig)?;
            },
            WaitStatus::PtraceEvent(child, signal::SIGTRAP, PTRACE_EVENT_VFORK) => {
                let sig = if check_parents(&ignored_parents, child) {
                    Some(signal::SIGTRAP)
                } else {
                    None
                };
                continue_exec(child, sig)?;
            },
            WaitStatus::PtraceEvent(child, signal::SIGTRAP, PTRACE_EVENT_EXEC) => {
                println!("Exec event {:?}", get_event_data(child));
                ignored_parents.insert(child);
                detach_child(child)?;
                   // continue_exec(child, Some(signal::SIGTRAP))?; // <- this right?
            },
            WaitStatus::PtraceEvent(child, signal::SIGTRAP, PTRACE_EVENT_EXIT) => {
                let sig = if check_parents(&ignored_parents, child) {
                    Some(signal::SIGTRAP)
                } else {
                    thread_count -= 1;
                    None
                };
                continue_exec(child, sig)?;
            },
            WaitStatus::Signaled(child, signal::SIGTRAP, true) => {
                let sig = if check_parents(&ignored_parents, child) {
                    Some(signal::SIGTRAP)
                } else {
                    None
                };
                continue_exec(child, sig)?;
            },
            s => {
                println!("Unexpected stop {:?}", s);
                break;
            },
        }
    }
    Ok(res)
}
