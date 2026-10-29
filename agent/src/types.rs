#![allow(dead_code, non_camel_case_types)]
//! Rust mirror of `core/include/kinnector/telemetry.h`, the frames core writes on the telemetry
//! socket (SOCK_STREAM, back to back, no length prefix: a wrong frame size misreads every event
//! after the first).
//!
//! There is no wire version field, so this file must follow that header by hand. The sizes below
//! are core's own `static_assert`s; the compile-time checks at the bottom make an edit that
//! forgets a struct fail the build, and `build.rs` fails it when core's header asserts other
//! sizes than these. Detail structs only need to be a correct PREFIX of core's (core appends
//! fields at the end and the union keeps its size), but here they mirror core in full.
use serde::{Deserialize, Serialize};

/// core/include/kinnector/telemetry.h: `static_assert(sizeof(TelemetryHeader) == 30, ...)`
pub const EXPECTED_HEADER_SIZE: usize = 30;
/// core/include/kinnector/telemetry.h: `static_assert(sizeof(TelemetryEvent) == 1608, ...)`
pub const EXPECTED_EVENT_SIZE: usize = 1608;
/// `sizeof(TelemetryEvent::details)`, the union; its largest member is `ProcessCreateDetails`.
pub const DETAILS_SIZE: usize = EXPECTED_EVENT_SIZE - EXPECTED_HEADER_SIZE;
/// One wire frame.
pub const RAW_EVENT_SIZE: usize = EXPECTED_EVENT_SIZE;

/// Core's event numbers. Read off the wire through [`TelemetryHeader::event_type`]: core sends
/// numbers this agent has no arm for (antitheft and Windows/macOS events), and a raw byte read
/// straight into a Rust enum with no such variant is undefined behaviour.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    ProcessCreate = 1,
    ProcessStop = 2,
    FileRead = 3,
    FileCreate = 4,
    FileWrite = 5,
    FileRename = 6,
    NetworkConnect = 7,
    ImageLoad = 8,
    RegistryWrite = 9,
    ClipboardWrite = 10,
    CallStackFrame = 11,
    MemoryProtect = 12,
    PtraceAttach = 13,
    SSHAuth = 14,
    TerminalCommand = 15,
    FileOpen = 16,
    MemoryMap = 17,
    Dup2 = 18,
    Listen = 19,
    NetworkAccept = 20,
    DNSQuery = 21,
    FileDelete = 22,
    SignalDelivery = 23,
    PrivilegeChange = 24,
    IPCAccess = 25,
    /// Was 26 here, which core numbers `TaskRegistered`; core moved it to 42.
    FileBatch = 42,
}

impl EventType {
    pub fn from_raw(v: u8) -> Option<Self> {
        use EventType::*;
        Some(match v {
            1 => ProcessCreate,
            2 => ProcessStop,
            3 => FileRead,
            4 => FileCreate,
            5 => FileWrite,
            6 => FileRename,
            7 => NetworkConnect,
            8 => ImageLoad,
            9 => RegistryWrite,
            10 => ClipboardWrite,
            11 => CallStackFrame,
            12 => MemoryProtect,
            13 => PtraceAttach,
            14 => SSHAuth,
            15 => TerminalCommand,
            16 => FileOpen,
            17 => MemoryMap,
            18 => Dup2,
            19 => Listen,
            20 => NetworkAccept,
            21 => DNSQuery,
            22 => FileDelete,
            23 => SignalDelivery,
            24 => PrivilegeChange,
            25 => IPCAccess,
            42 => FileBatch,
            _ => return None,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TelemetrySource {
    ETW = 1,
    ESF = 2,
    OpenBSM = 3,
    eBPF = 4,
    fanotify = 5,
    BPF_LSM = 6,
    Log_FIM = 7,
    Clipboard = 8,
    CallStack = 9,
    DirWatch = 10,
    FileGuard = 11,
    Wmi = 12,
    GuardedNoData = 13,
}

impl TelemetrySource {
    pub fn from_raw(v: u8) -> Option<Self> {
        use TelemetrySource::*;
        Some(match v {
            1 => ETW,
            2 => ESF,
            3 => OpenBSM,
            4 => eBPF,
            5 => fanotify,
            6 => BPF_LSM,
            7 => Log_FIM,
            8 => Clipboard,
            9 => CallStack,
            10 => DirWatch,
            11 => FileGuard,
            12 => Wmi,
            13 => GuardedNoData,
            _ => return None,
        })
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TelemetryHeader {
    pub sequence_number: u64,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub event_type_raw: u8,
    pub source_raw: u8,
    /// Windows-populated reuse-resistant identity; 0 ("unavailable") on Linux.
    pub actor_sequence_number: u64,
}

impl TelemetryHeader {
    pub fn new(sequence_number: u64, timestamp_ns: u64, pid: u32, event_type: EventType, source: TelemetrySource) -> Self {
        TelemetryHeader {
            sequence_number,
            timestamp_ns,
            pid,
            event_type_raw: event_type as u8,
            source_raw: source as u8,
            actor_sequence_number: 0,
        }
    }

    /// `None` for an event number this agent does not handle.
    pub fn event_type(&self) -> Option<EventType> {
        EventType::from_raw(self.event_type_raw)
    }

    pub fn source(&self) -> Option<TelemetrySource> {
        TelemetrySource::from_raw(self.source_raw)
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessCreateDetails {
    pub child_pid: u32,
    pub real_parent_pid: u32,
    pub child_image_path: [u8; 512],
    pub child_command_line: [u8; 1024],
    pub child_sequence_number: u64,
    pub parent_sequence_number: u64,
    pub mnt_ns_inum: u32,
    pub pid_ns_inum: u32,
    pub child_start_time: u64,
    pub pkg_lifecycle: u8,
    pub kernel_verdicts: u8,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessStopDetails {
    pub exit_code: i32,
    pub _reserved: u32,
    pub sequence_number: u64,
    pub create_time: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileReadDetails {
    pub bytes_requested: u32,
    pub zone_id: i32,
    pub file_path: [u8; 512],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileCreateDetails {
    pub zone_id: i32,
    pub file_path: [u8; 512],
    pub create_options: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileWriteDetails {
    pub bytes_written: u32,
    pub file_path: [u8; 512],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileRenameDetails {
    pub source_path: [u8; 512],
    pub destination_path: [u8; 512],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NetworkConnectDetails {
    pub destination_ip: [u8; 46],
    pub destination_port: u16,
    pub protocol: [u8; 8],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageLoadDetails {
    pub is_signed: u8,
    pub module_path: [u8; 512],
    pub signer_subject: [u8; 256],
    pub verdict: u8,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RegistryWriteDetails {
    pub key_path: [u8; 512],
    pub value_name: [u8; 256],
    pub value_data: [u8; 512],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ClipboardWriteDetails {
    pub owner_pid: u32,
    pub owner_is_foreground: u8,
    pub previous_content: [u8; 512],
    pub new_content: [u8; 512],
    pub content_type: [u8; 32],
    pub attribution: [u8; 16],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CallStackFrameDetails {
    pub frame_index: u32,
    pub return_address: u64,
    pub is_file_backed: u8,
    pub module_path: [u8; 512],
    pub notes: [u8; 128],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryProtectDetails {
    pub target_pid: u32,
    pub address: u64,
    pub length: u64,
    pub prot_flags: [u8; 64],
    pub old_prot_flags: [u8; 64],
    pub target_start_time: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PtraceAttachDetails {
    pub target_pid: u32,
    pub mode: [u8; 32],
    pub target_start_time: u64,
    pub verdict: u8,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SSHAuthDetails {
    pub username: [u8; 64],
    pub source_ip: [u8; 46],
    pub port: u16,
    pub auth_method: [u8; 32],
    pub status: [u8; 16],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TerminalCommandDetails {
    pub tty_device: [u8; 32],
    pub command: [u8; 512],
}

/// Core sends FileOpen only in antitheft mode and for persistence writes: the opened file's
/// identity, a verdict, and its LEAF name (not a path). Nothing in core emits it for Vandam mode.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileOpenDetails {
    pub resource_dev: u64,
    pub resource_ino: u64,
    pub verdict: u8,
    pub file_path: [u8; 512],
    /// KINN_OPEN_* bits: 0x01 read, 0x02 write, 0x04 O_TRUNC, 0x80 known. 0 = unknown.
    pub access_mode: u8,
    pub response: u8,
    pub pkg_lifecycle: u8,
    pub persist_op: u8,
    pub parent_pid: u32,
    pub process_start_time: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryMapDetails {
    pub address: u64,
    pub length: u64,
    pub prot_flags: u32,   // PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
    pub map_flags: u32,    // MAP_PRIVATE=2, MAP_ANONYMOUS=32
    pub fd: i32,           // -1 = anonymous mapping
    pub file_inode: u64,
    pub target_start_time: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Dup2Details {
    pub old_fd: i32,
    pub new_fd: i32,
    pub old_fd_type: u8,   // 0=unknown, 1=file, 2=socket, 3=pipe
    pub old_fd_family: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NetworkAcceptDetails {
    pub source_ip: [u8; 46],
    pub source_port: u16,
    pub local_port: u16,
}

/// No struct in core's union: `kinnector_container_lsm_hooks.h` writes these offsets by hand
/// (name at 0, server address at 128, port big-endian at 174).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DNSQueryDetails {
    pub query_name: [u8; 128],
    pub server_ip: [u8; 46],
    pub server_port: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileDeleteDetails {
    pub file_path: [u8; 512],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SignalDeliveryDetails {
    pub target_pid: u32,
    pub signal: i32,
    pub verdict: u8,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PrivilegeChangeDetails {
    pub old_uid: u32,
    pub new_uid: u32,
    pub old_euid: u32,
    pub new_euid: u32,
    pub old_suid: u32,
    pub new_suid: u32,
    pub old_fsuid: u32,
    pub new_fsuid: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IPCAccessDetails {
    pub shmid: i32,
    pub creator_uid: u32,
}

/// No struct in core's union: `kinnector_helpers.h` writes op at 0, count at 4, path at 8.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileBatchDetails {
    pub op_type: u32, // 1=Read, 2=Write, 3=Delete, 4=MmapExec, 5=Exec, 6=Syscall
    pub count: u32,
    pub file_path: [u8; 256],
}

/// Mirrors `TelemetryEvent`: the header plus the union's raw bytes.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TelemetryEventRaw {
    pub header: TelemetryHeader,
    pub details_buffer: [u8; DETAILS_SIZE],
}

const _: () = assert!(
    std::mem::size_of::<TelemetryHeader>() == EXPECTED_HEADER_SIZE,
    "TelemetryHeader no longer matches core/include/kinnector/telemetry.h"
);
const _: () = assert!(
    std::mem::size_of::<TelemetryEventRaw>() == EXPECTED_EVENT_SIZE,
    "TelemetryEventRaw no longer matches core/include/kinnector/telemetry.h"
);
const _: () = assert!(
    std::mem::size_of::<ProcessCreateDetails>() == DETAILS_SIZE,
    "ProcessCreateDetails is the union's largest member: it must fill it exactly"
);
const _: () = assert!(std::mem::size_of::<FileOpenDetails>() == 545);
mod core_abi {
    include!(concat!(env!("OUT_DIR"), "/core_abi.rs"));
}
const _: () = assert!(
    core_abi::CORE_HEADER_SIZE == EXPECTED_HEADER_SIZE && core_abi::CORE_EVENT_SIZE == EXPECTED_EVENT_SIZE,
    "core's telemetry.h now asserts other frame sizes: re-derive this file from it"
);
