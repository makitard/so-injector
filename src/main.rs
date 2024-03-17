use std::{ffi::{CStr, CString}, fs::OpenOptions, io::{Read, Seek, SeekFrom, Write}};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    pid: u32,
    library: String,
}

unsafe fn error_check(message: &str, return_value: i64) {
    if return_value != 0 {
        println!(
            "{message}: {}",
            CStr::from_ptr(libc::strerror(*libc::__errno_location())).to_string_lossy()
        );
        std::process::exit(1);
    }
}

fn main() {
    let args = Args::parse();

    let (tx, rx) = std::sync::mpsc::channel::<i32>();
    let pid = args.pid;

    unsafe {
        error_check(
            "Unable to attach to target process",
            libc::ptrace(libc::PTRACE_SEIZE, args.pid, 0, 0),
        );

        error_check(
            "Unable to pause target process",
            libc::ptrace(libc::PTRACE_INTERRUPT, args.pid, 0, 0),
        );
    }

    let bytes = std::fs::read(format!("/proc/{}/exe", args.pid)).unwrap();
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    let dlopen_candidates = elf.libraries.into_iter().map(|x| {
        let mut info: Option<(usize, String)> = None;
        for map in procfs::process::Process::new(args.pid as _).unwrap().maps().unwrap() {
            if let procfs::process::MMapPath::Path(path) = map.pathname {
                if path.to_string_lossy().contains(x) && (map.address.0 as usize) < info.clone().map(|x| x.0).unwrap_or(usize::MAX) {
                    info = Some((map.address.0 as usize, path.to_string_lossy().to_string()));
                }
            }
        }

        info
    }).flatten().map(|(start_addr, library_path)| {
        if let Ok(bytes) = std::fs::read(&library_path) {
            let elf = goblin::elf::Elf::parse(&bytes).unwrap();

            for dynsym in elf.dynsyms.iter() {
                if let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) {
                    if name == "dlopen" && dynsym.st_value != 0 {
                        return Some(start_addr as u64 + dynsym.st_value);
                    }
                }
            }
        }

        None
    }).flatten().collect::<Vec<u64>>();

    if dlopen_candidates.is_empty() {
        println!("Couldn't find dlopen symbol in target process");
        std::process::exit(1);
    }

    let dlopen_address = dlopen_candidates[0];
    
    let mut original_context: libc::user_regs_struct = unsafe { std::mem::zeroed() };

    unsafe {
        error_check(
            "Unable to get registers",
            libc::ptrace(
                libc::PTRACE_GETREGS,
                args.pid,
                0,
                &mut original_context as *mut _ as usize,
            ),
        )
    }

    let mut new_context = original_context.clone();

    let mut mem = OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/proc/{}/mem", args.pid))
        .unwrap();

    //overwrite instruction at rip so we can detect when dlopen returns

    mem.seek(SeekFrom::Start(original_context.rip)).unwrap();
    //15 is the maximum size of an x86 instruction [https://cdrdv2.intel.com/v1/dl/getContent/671200 (Intel® 64 and IA-32 Architectures Software Developer’s Manual) @ 2.3.11]
    let mut old_bytes = [0u8; 15];
    mem.read_exact(&mut old_bytes).unwrap();

    mem.seek(SeekFrom::Start(original_context.rip)).unwrap();
    mem.write_all(&vec![0xcc; old_bytes.len()]).unwrap(); //int3


    let c_library = CString::new(args.library.clone()).unwrap();
    let c_library = c_library.as_bytes_with_nul();

    //write library path to stack
    mem.seek(SeekFrom::Start(new_context.rsp - c_library.len() as u64)).unwrap();
    mem.write_all(c_library).unwrap();

    new_context.rsp -= c_library.len() as u64;

    //arg1
    new_context.rdi = new_context.rsp;

    //arg2
    new_context.rax = 0;

    //arg1 again but on the stack
    //why is this neccessary? :(
    //TODO figure out why LOL
    mem.seek(SeekFrom::Start(new_context.rsp - 8)).unwrap();
    mem.write_all(&original_context.rsp.to_le_bytes()).unwrap();

    new_context.rsp -= 8;

    //push return address
    mem.seek(SeekFrom::Start(new_context.rsp - 8)).unwrap();
    mem.write_all(&original_context.rip.to_le_bytes()).unwrap();

    new_context.rsp -= 8;

    //call
    new_context.rip = dlopen_address;

    unsafe {
        let _waitpid_thread = std::thread::spawn(move || {
            let mut status = 0i32;
            while libc::waitpid(pid as i32, &mut status as _, libc::__WALL) != -1 {
                println!("status {}", libc::WSTOPSIG(status));
                let _ = tx.send(status);
            }
        });

        error_check(
            "Unable to set registers",
            libc::ptrace(
                libc::PTRACE_SETREGS,
                args.pid,
                0,
                &new_context as *const _ as usize,
            ),
        );
    }

    unsafe {
        error_check(
            "Unable to resume target process",
            libc::ptrace(libc::PTRACE_CONT, args.pid , 0, 0),
        );

        libc::ptrace(libc::PTRACE_CONT, args.pid , 0, 0);
    }

    if let Ok(signal) = rx.recv() {
        if libc::WSTOPSIG(signal) == libc::SIGTRAP {
            unsafe {
                error_check(
                    "Unable to stop process (on SIGTRAP)",
                    libc::ptrace(
                        libc::PTRACE_INTERRUPT,
                        args.pid,
                        0,
                        0,
                    ),
                );
            }
        } else {
            println!("Unexpected signal: {}", libc::WSTOPSIG(signal));
            std::process::exit(1);
        }
    }

    unsafe {
        error_check(
            "Unable to get final registers",
            libc::ptrace(
                libc::PTRACE_GETREGS,
                args.pid,
                0,
                &mut new_context as *mut _ as usize,
            ),
        );
    }

    if new_context.rax != 0 {
        println!("Loaded {} at address {:#016x}", args.library, new_context.rax);
    } else {
        //TODO: display tracee errno
        println!("Failed to load library, return value: {}", new_context.rax as i64);
    }

    mem.seek(SeekFrom::Start(original_context.rip)).unwrap();
    mem.write_all(&old_bytes).unwrap();

    //restore registers and detach
    unsafe {
        error_check(
            "Unable to restore registers",
            libc::ptrace(
                libc::PTRACE_SETREGS,
                args.pid ,
                0,
                &original_context as *const _ as usize,
            ),
        );

        error_check(
            "Unable to detach from process",
            libc::ptrace(
                libc::PTRACE_DETACH,
                args.pid ,
                0,
                0,
            ),
        );
    }
}
