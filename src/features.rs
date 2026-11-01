//! Feature extraction. One pass over the file produces a fixed-order numeric
//! vector (for the models) plus rule findings with evidence (for humans).
//!
//! The same code produces training features (`ratel features`) and scan-time
//! features, so the model never sees a feature computed differently.

use crate::indicators::*;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// Capabilities the scanner reports. Order is the model order.
pub const CAPS: &[&str] = &["anti_debug", "anti_vm", "obfuscation", "packed", "crypto", "network"];

pub const FEATURE_NAMES: &[&str] = &[
    // --- file / format
    "fmt_pe", "fmt_elf", "is_64", "size_log2", "parse_error", "is_dll", "is_dotnet", "is_static",
    "stripped", "n_sections", "exec_sections", "wx_sections", "nonstd_sections", "packer_section",
    "upx_marker", "entry_anomaly", "entry_in_last_section", "vsize_gt_raw", "no_section_headers",
    "n_imports_log", "n_libs", "ordinal_imports", "few_imports", "tls_callbacks", "signed",
    "overlay_ratio", "overlay_entropy", "rsrc_ratio", "rsrc_entropy",
    // --- entropy
    "entropy", "entropy_max_win", "frac_high_win", "frac_low_win", "exec_entropy_max",
    "exec_entropy_mean", "data_entropy_max", "printable_ratio",
    // --- imports / APIs
    "api_antidbg", "api_timing", "api_sysinfo", "api_dynres", "api_mem", "api_net", "api_crypto",
    "api_proc", "api_isdebuggerpresent", "api_checkremotedbg", "api_ntqip", "api_ntsetinfothread",
    "api_outputdebugstring", "api_ptrace", "api_prctl", "api_getprocaddress", "api_virtualprotect",
    "api_virtualalloc", "api_memfd", "api_injection", "api_toolhelp", "api_memstatus",
    "api_firmware", "api_userinput", "api_http", "api_socket", "api_dns", "api_wincrypt",
    "api_openssl", "dyn_api_strings",
    // --- strings
    "str_vm_vendor", "str_vm_artifact", "str_sandbox", "str_dbg_tools", "str_dbg_checks",
    "str_net", "str_crypto", "str_exec", "strings_per_kb", "str_mean_len", "rand_str_ratio",
    "b64_strs", "hex_strs", "urls", "ipv4s", "domains",
    // --- crypto constants
    "cc_aes_sbox", "cc_aes_invsbox", "cc_aes_ttable", "cc_sha256", "cc_sha512", "cc_md5",
    "cc_crc32", "cc_blowfish", "cc_chacha", "cc_des", "cc_rsa_oid", "cc_base64",
    // --- instructions
    "code_bytes_log2", "n_insn_log2", "invalid_ratio", "cpuid", "cpuid_hv_leaf", "cpuid_leaf1",
    "cpuid_hvbit", "rdtsc", "inline_int3", "int2d", "int_03", "icebp", "redpill", "io_port",
    "vmware_backdoor", "vmcall", "pushf_popf", "trap_flag", "peb_access", "kuser_shared",
    "raw_syscalls", "sys_ptrace", "sys_prctl", "sys_memfd", "sys_mprotect", "sys_execve",
    "sys_socket", "aesni", "sha_ni", "pclmul", "imm_tea", "imm_sha", "imm_md5", "imm_chacha",
    "imm_crc32", "imm_vm", "imm_apihash", "ror13", "rot_rate", "xor_rate", "xor_imm_rate",
    "call_reg_rate", "jmp_reg_rate", "rand_cmp_rate", "rand_cmp", "stackstr_runs",
    "stackstr_dword_rate", "antidisasm_jcc", "call_next", "entry_pushad", "ud2_rate",
];

pub fn feature_index() -> &'static HashMap<&'static str, usize> {
    static IDX: OnceLock<HashMap<&'static str, usize>> = OnceLock::new();
    IDX.get_or_init(|| FEATURE_NAMES.iter().enumerate().map(|(i, n)| (*n, i)).collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Elf,
    Pe,
    Other,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Finding {
    pub cap: &'static str,
    pub rule: &'static str,
    /// 1 = weak hint, 2 = moderate, 3 = strong on its own.
    pub strength: u8,
    pub evidence: String,
}

pub struct Analysis {
    pub format: Format,
    pub feats: Vec<f32>,
    pub findings: Vec<Finding>,
}

struct Fv {
    v: Vec<f32>,
}
impl Fv {
    fn set(&mut self, k: &str, x: f32) {
        let i = *feature_index().get(k).unwrap_or_else(|| panic!("unknown feature {k}"));
        self.v[i] = x;
    }
    #[allow(dead_code)]
    fn add(&mut self, k: &str, x: f32) {
        let i = *feature_index().get(k).unwrap_or_else(|| panic!("unknown feature {k}"));
        self.v[i] += x;
    }
    fn get(&self, k: &str) -> f32 {
        self.v[feature_index()[k]]
    }
}

fn shannon(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut h = [0u32; 256];
    for &b in data {
        h[b as usize] += 1;
    }
    let n = data.len() as f32;
    h.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f32 / n;
        -p * p.log2()
    }).sum()
}

fn log2p(x: f32) -> f32 {
    (1.0 + x).log2()
}

/// An executable region of the file to disassemble.
struct CodeRegion {
    off: usize,
    len: usize,
    vaddr: u64,
}

struct Parsed {
    /// false for non-x86 machines and .NET assemblies: don't disassemble.
    x86: bool,
    imports: Vec<String>,
    code: Vec<CodeRegion>,
    bitness: u32,
    entry_off: Option<usize>,
}

pub fn analyze(data: &[u8]) -> Analysis {
    let mut f = Fv { v: vec![0.0; FEATURE_NAMES.len()] };
    let mut findings = Vec::new();
    let format = if data.starts_with(b"\x7fELF") {
        Format::Elf
    } else if data.starts_with(b"MZ") {
        Format::Pe
    } else {
        Format::Other
    };
    f.set("fmt_pe", (format == Format::Pe) as u8 as f32);
    f.set("fmt_elf", (format == Format::Elf) as u8 as f32);
    f.set("size_log2", log2p(data.len() as f32));

    entropy_features(data, &mut f);

    let parsed = match format {
        Format::Pe => parse_pe(data, &mut f, &mut findings),
        Format::Elf => parse_elf(data, &mut f, &mut findings),
        Format::Other => None,
    };
    let parsed = parsed.unwrap_or_else(|| {
        if format != Format::Other {
            f.set("parse_error", 1.0);
            findings.push(Finding { cap: "packed", rule: "malformed_headers", strength: 2,
                evidence: "headers fail to parse (truncated or deliberately malformed)".into() });
        }
        // Fall back to sweeping the whole file only for tiny raw blobs (shellcode-like).
        Parsed { x86: false, imports: vec![], code: vec![], bitness: 64, entry_off: None }
    });
    f.set("is_64", (parsed.bitness == 64) as u8 as f32);

    import_features(&parsed.imports, &mut f, &mut findings);
    string_features(data, &parsed.imports, &mut f, &mut findings);
    crypto_const_features(data, &mut f, &mut findings);
    code_features(data, &parsed, &mut f, &mut findings);
    let few = f.get("n_imports_log") <= log2p(8.0) && f.get("is_static") == 0.0 && f.get("is_dotnet") == 0.0;
    f.set("few_imports", few as u8 as f32);
    derived_rules(&f, &mut findings);

    Analysis { format, feats: f.v, findings }
}

fn entropy_features(data: &[u8], f: &mut Fv) {
    f.set("entropy", shannon(data));
    const W: usize = 4096;
    let (mut n, mut hi, mut lo, mut mx) = (0u32, 0u32, 0u32, 0f32);
    for w in data.chunks(W) {
        if w.len() < 512 {
            continue;
        }
        let e = shannon(w);
        n += 1;
        if e > 7.2 {
            hi += 1;
        }
        if e < 1.0 {
            lo += 1;
        }
        mx = mx.max(e);
    }
    if n > 0 {
        f.set("frac_high_win", hi as f32 / n as f32);
        f.set("frac_low_win", lo as f32 / n as f32);
    }
    f.set("entropy_max_win", mx);
    let printable = data.iter().filter(|&&b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\t').count();
    f.set("printable_ratio", printable as f32 / data.len().max(1) as f32);
}

fn section_is_std(name: &str) -> bool {
    let n = name.trim_end_matches('\0');
    STD_SECTIONS.iter().any(|s| n == *s || (s.len() > 1 && n.starts_with(&format!("{s}."))))
        || n.starts_with(".debug") || n.starts_with(".note") || n.starts_with(".rela")
        || n.starts_with(".rel.") || n.starts_with(".gnu") || n.starts_with(".text.")
        || n.starts_with(".rodata.") || n.starts_with(".data.") || n.starts_with(".bss.")
        || n.starts_with(".tbss.") || n.starts_with(".tdata.") || n.starts_with(".idata$")
        || n.starts_with(".llvm") || n.starts_with("__") || n.starts_with(".zdebug") || n.is_empty()
}

fn packer_section_name(name: &str) -> bool {
    let n = name.trim_end_matches('\0').to_ascii_lowercase();
    PACKER_SECTIONS.iter().any(|p| n == *p)
}

fn parse_pe(data: &[u8], f: &mut Fv, findings: &mut Vec<Finding>) -> Option<Parsed> {
    use goblin::pe::{options::ParseOptions, PE};
    let mut opts = ParseOptions::default();
    opts.parse_attribute_certificates = false;
    opts.resolve_rva = true;
    let pe = PE::parse_with_opts(data, &opts).ok()?;
    let bitness = if pe.is_64 { 64 } else { 32 };
    f.set("is_dll", pe.is_lib as u8 as f32);
    f.set("n_sections", pe.sections.len() as f32);
    let oh = pe.header.optional_header.as_ref();
    let dd = oh.map(|o| &o.data_directories);
    let is_dotnet = dd.and_then(|d| d.get_clr_runtime_header()).map_or(false, |d| d.size > 0);
    f.set("is_dotnet", is_dotnet as u8 as f32);
    if let Some(c) = dd.and_then(|d| d.get_certificate_table()) {
        f.set("signed", (c.size > 0) as u8 as f32);
    }

    let mut code = Vec::new();
    let (mut execn, mut wx, mut nonstd, mut packer, mut vgt) = (0, 0, 0, 0, 0);
    let mut exec_ent: Vec<f32> = vec![];
    let mut data_ent_max = 0f32;
    let mut max_raw_end = 0usize;
    let entry = pe.entry as u32;
    let mut entry_sec: Option<usize> = None;
    let mut entry_off = None;
    for (i, s) in pe.sections.iter().enumerate() {
        let name = s.name().unwrap_or("").to_string();
        let ch = s.characteristics;
        let exec = ch & 0x2000_0000 != 0 || ch & 0x20 != 0;
        let write = ch & 0x8000_0000 != 0;
        let off = s.pointer_to_raw_data as usize;
        let raw = s.size_of_raw_data as usize;
        let end = off.saturating_add(raw).min(data.len());
        if off < data.len() {
            max_raw_end = max_raw_end.max(end);
        }
        let bytes = if off < end { &data[off..end] } else { &[][..] };
        let e = shannon(bytes);
        if exec {
            execn += 1;
            exec_ent.push(e);
            let len = (s.virtual_size as usize).min(raw).max(if s.virtual_size == 0 { raw } else { 0 });
            let len = len.min(end.saturating_sub(off));
            if len > 0 {
                code.push(CodeRegion { off, len, vaddr: pe.image_base + s.virtual_address as u64 });
            }
            if raw == 0 || s.virtual_size as usize > 2 * raw.max(1) {
                vgt += 1;
            }
        } else if bytes.len() >= 1024 {
            data_ent_max = data_ent_max.max(e);
        }
        if exec && write {
            wx += 1;
            findings.push(Finding { cap: "packed", rule: "wx_section", strength: 2,
                evidence: format!("section {name:?} is writable+executable") });
        }
        if packer_section_name(&name) {
            packer += 1;
            findings.push(Finding { cap: "packed", rule: "packer_section", strength: 3,
                evidence: format!("packer/protector section name {name:?}") });
        } else if !section_is_std(&name) {
            nonstd += 1;
        }
        let va = s.virtual_address;
        let vs = s.virtual_size.max(s.size_of_raw_data);
        if entry >= va && entry < va.saturating_add(vs) {
            entry_sec = Some(i);
            if exec {
                entry_off = Some(off + (entry - va) as usize);
            }
            if !exec {
                f.set("entry_anomaly", 1.0);
            }
        }
    }
    if entry != 0 && entry_sec.is_none() && !pe.is_lib {
        f.set("entry_anomaly", 1.0);
    }
    if let Some(i) = entry_sec {
        if i + 1 == pe.sections.len() && pe.sections.len() > 1 {
            f.set("entry_in_last_section", 1.0);
        }
    }
    f.set("exec_sections", execn as f32);
    f.set("wx_sections", wx as f32);
    f.set("nonstd_sections", nonstd as f32);
    f.set("packer_section", packer as f32);
    f.set("vsize_gt_raw", vgt as f32);
    f.set("exec_entropy_max", exec_ent.iter().cloned().fold(0.0, f32::max));
    if !exec_ent.is_empty() {
        f.set("exec_entropy_mean", exec_ent.iter().sum::<f32>() / exec_ent.len() as f32);
    }
    f.set("data_entropy_max", data_ent_max);

    // Overlay: bytes past the last section's raw data (minus an appended signature).
    let mut overlay_end = data.len();
    if let Some(c) = dd.and_then(|d| d.get_certificate_table()) {
        let co = c.virtual_address as usize; // file offset for the cert table
        if c.size > 0 && co >= max_raw_end && co < overlay_end {
            overlay_end = co;
        }
    }
    if max_raw_end > 0 && overlay_end > max_raw_end {
        let ov = &data[max_raw_end..overlay_end];
        f.set("overlay_ratio", ov.len() as f32 / data.len() as f32);
        f.set("overlay_entropy", shannon(ov));
    }
    if let Some(r) = dd.and_then(|d| d.get_resource_table()) {
        if r.size > 0 {
            if let Some(off) = rva_to_off(&pe.sections, r.virtual_address) {
                let end = off.saturating_add(r.size as usize).min(data.len());
                if off < end {
                    f.set("rsrc_ratio", (end - off) as f32 / data.len() as f32);
                    f.set("rsrc_entropy", shannon(&data[off..end]));
                }
            }
        }
    }
    let tls = pe.tls_data.as_ref().map_or(0, |t| t.callbacks.len());
    f.set("tls_callbacks", tls as f32);
    if tls > 0 {
        findings.push(Finding { cap: "anti_debug", rule: "tls_callbacks", strength: 1,
            evidence: format!("{tls} TLS callback(s) run before the entry point") });
    }
    let mut imports: Vec<String> = Vec::new();
    let mut ord = 0;
    for imp in &pe.imports {
        if imp.name.starts_with("ORDINAL ") {
            ord += 1;
        } else {
            imports.push(imp.name.to_string());
        }
    }
    f.set("ordinal_imports", ord as f32);
    f.set("n_libs", pe.libraries.len() as f32);
    f.set("is_static", (pe.imports.is_empty()) as u8 as f32);
    f.set("stripped", 1.0);
    if memmem(&data[..data.len().min(8192)], b"UPX!").is_some() {
        f.set("upx_marker", 1.0);
    }
    let x86 = matches!(pe.header.coff_header.machine, 0x14c | 0x8664) && !is_dotnet;
    Some(Parsed { x86, imports, code, bitness, entry_off })
}

fn rva_to_off(secs: &[goblin::pe::section_table::SectionTable], rva: u32) -> Option<usize> {
    secs.iter().find(|s| rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size.max(s.size_of_raw_data))
        .map(|s| (rva - s.virtual_address + s.pointer_to_raw_data) as usize)
}

fn memmem(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn parse_elf(data: &[u8], f: &mut Fv, findings: &mut Vec<Finding>) -> Option<Parsed> {
    use goblin::elf::{program_header::*, section_header::*, Elf};
    let elf = Elf::parse(data).ok()?;
    let bitness = if elf.is_64 { 64 } else { 32 };
    f.set("is_dll", (elf.header.e_type == goblin::elf::header::ET_DYN && elf.interpreter.is_none()) as u8 as f32);
    f.set("is_static", elf.interpreter.is_none() as u8 as f32);
    f.set("n_sections", elf.section_headers.len() as f32);
    f.set("no_section_headers", elf.section_headers.is_empty() as u8 as f32);
    f.set("n_libs", elf.libraries.len() as f32);
    let has_symtab = elf.section_headers.iter().any(|s| s.sh_type == SHT_SYMTAB);
    f.set("stripped", (!has_symtab) as u8 as f32);

    let entry = elf.entry;
    let mut code = Vec::new();
    let (mut execn, mut wx, mut nonstd, mut packer) = (0, 0, 0, 0);
    let mut exec_ent = vec![];
    let mut data_ent_max = 0f32;
    let mut entry_in_exec = false;
    let mut entry_off = None;
    let mut max_end = 0usize;
    let mut last_alloc: Option<(u64, u64)> = None;
    for s in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(s.sh_name).unwrap_or("");
        let off = s.sh_offset as usize;
        let size = s.sh_size as usize;
        if s.sh_type != SHT_NOBITS {
            max_end = max_end.max(off.saturating_add(size).min(data.len()));
        }
        if s.sh_flags & SHF_ALLOC as u64 != 0 {
            last_alloc = Some((s.sh_addr, s.sh_size));
        }
        let exec = s.sh_flags & SHF_EXECINSTR as u64 != 0;
        let write = s.sh_flags & SHF_WRITE as u64 != 0;
        let end = off.saturating_add(size).min(data.len());
        let bytes = if s.sh_type != SHT_NOBITS && off < end { &data[off..end] } else { &[][..] };
        if exec {
            execn += 1;
            exec_ent.push(shannon(bytes));
            if !bytes.is_empty() {
                code.push(CodeRegion { off, len: bytes.len(), vaddr: s.sh_addr });
            }
            if entry >= s.sh_addr && entry < s.sh_addr + s.sh_size {
                entry_in_exec = true;
                entry_off = Some(off + (entry - s.sh_addr) as usize);
            }
        } else if bytes.len() >= 1024 && s.sh_flags & SHF_ALLOC as u64 != 0 {
            data_ent_max = data_ent_max.max(shannon(bytes));
        }
        if exec && write {
            wx += 1;
            findings.push(Finding { cap: "packed", rule: "wx_section", strength: 2,
                evidence: format!("section {name:?} is writable+executable") });
        }
        if packer_section_name(name) {
            packer += 1;
        } else if !section_is_std(name) {
            nonstd += 1;
        }
    }
    let _ = last_alloc;
    let mut rwx_seg = false;
    for ph in &elf.program_headers {
        let end = (ph.p_offset.saturating_add(ph.p_filesz)) as usize;
        max_end = max_end.max(end.min(data.len()));
        if ph.p_type == PT_LOAD && ph.p_flags & PF_X != 0 && ph.p_flags & PF_W != 0 {
            rwx_seg = true;
        }
        if elf.section_headers.is_empty() && ph.p_type == PT_LOAD && ph.p_flags & PF_X != 0 {
            let off = ph.p_offset as usize;
            let len = (ph.p_filesz as usize).min(data.len().saturating_sub(off));
            if len > 0 {
                exec_ent.push(shannon(&data[off..off + len]));
                code.push(CodeRegion { off, len, vaddr: ph.p_vaddr });
                execn += 1;
            }
            if entry >= ph.p_vaddr && entry < ph.p_vaddr + ph.p_filesz {
                entry_in_exec = true;
                entry_off = Some(off + (entry - ph.p_vaddr) as usize);
            }
        }
    }
    if rwx_seg {
        wx += 1;
        findings.push(Finding { cap: "packed", rule: "rwx_segment", strength: 2,
            evidence: "a PT_LOAD segment is mapped writable+executable".into() });
    }
    if entry != 0 && !entry_in_exec {
        f.set("entry_anomaly", 1.0);
    }
    if elf.section_headers.is_empty() {
        findings.push(Finding { cap: "packed", rule: "no_section_headers", strength: 1,
            evidence: "ELF has no section headers (stripped hard or packed)".into() });
    }
    f.set("exec_sections", execn as f32);
    f.set("wx_sections", wx as f32);
    f.set("nonstd_sections", nonstd as f32);
    f.set("packer_section", packer as f32);
    f.set("exec_entropy_max", exec_ent.iter().cloned().fold(0.0, f32::max));
    if !exec_ent.is_empty() {
        f.set("exec_entropy_mean", exec_ent.iter().sum::<f32>() / exec_ent.len() as f32);
    }
    f.set("data_entropy_max", data_ent_max);
    if max_end > 0 && max_end < data.len() {
        let ov = &data[max_end..];
        f.set("overlay_ratio", ov.len() as f32 / data.len() as f32);
        f.set("overlay_entropy", shannon(ov));
    }
    if memmem(&data[..data.len().min(8192)], b"UPX!").is_some()
        || memmem(&data[data.len().saturating_sub(8192)..], b"UPX!").is_some()
    {
        f.set("upx_marker", 1.0);
    }

    // Imports: undefined dynamic symbols; for static binaries with a symtab, the
    // linked-in libc function names stand in for imports.
    let mut imports = Vec::new();
    for s in elf.dynsyms.iter() {
        if s.st_shndx == 0 {
            if let Some(n) = elf.dynstrtab.get_at(s.st_name) {
                if !n.is_empty() {
                    imports.push(n.to_string());
                }
            }
        }
    }
    if elf.interpreter.is_none() && has_symtab {
        for s in elf.syms.iter() {
            if s.st_type() == goblin::elf::sym::STT_FUNC {
                if let Some(n) = elf.strtab.get_at(s.st_name) {
                    let n = n.trim_start_matches("__").trim_start_matches("libc_");
                    if !n.is_empty() {
                        imports.push(n.to_string());
                    }
                }
            }
        }
    }
    let x86 = matches!(elf.header.e_machine, goblin::elf::header::EM_X86_64 | goblin::elf::header::EM_386);
    Some(Parsed { x86, imports, code, bitness, entry_off })
}

fn import_features(imports: &[String], f: &mut Fv, findings: &mut Vec<Finding>) {
    let set: HashSet<&str> = imports.iter().map(|s| s.as_str()).collect();
    f.set("n_imports_log", log2p(set.len() as f32));
    for g in API_GROUPS {
        let n = g.apis.iter().filter(|a| set.contains(**a)).count();
        f.set(g.feature, n as f32);
    }
    for (feat, apis) in KEY_APIS {
        let hit: Vec<&str> = apis.iter().filter(|a| set.contains(**a)).cloned().collect();
        f.set(feat, (!hit.is_empty()) as u8 as f32);
        if hit.is_empty() {
            continue;
        }
        let (cap, strength) = match *feat {
            "api_isdebuggerpresent" | "api_checkremotedbg" | "api_ntsetinfothread" => ("anti_debug", 2),
            "api_ntqip" | "api_outputdebugstring" | "api_ptrace" => ("anti_debug", 1),
            "api_memfd" => ("packed", 2),
            "api_injection" => ("obfuscation", 1),
            "api_firmware" | "api_userinput" => ("anti_vm", 1),
            "api_http" => ("network", 2),
            "api_socket" | "api_dns" => ("network", 2),
            "api_wincrypt" | "api_openssl" => ("crypto", 2),
            _ => continue,
        };
        findings.push(Finding { cap, rule: feat, strength, evidence: format!("imports {}", hit.join(", ")) });
    }
}

struct StrMatchers {
    groups: AhoCorasick,
    group_of: Vec<usize>,
    pat_text: Vec<&'static str>,
    dyn_api: AhoCorasick,
    dyn_api_of: Vec<usize>,
}

fn utf16le(s: &str) -> Vec<u8> {
    s.bytes().flat_map(|b| [b, 0]).collect()
}

fn str_matchers() -> &'static StrMatchers {
    static M: OnceLock<StrMatchers> = OnceLock::new();
    M.get_or_init(|| {
        let mut pats: Vec<Vec<u8>> = vec![];
        let mut group_of = vec![];
        let mut pat_text = vec![];
        for (gi, g) in STR_GROUPS.iter().enumerate() {
            for p in g.pats {
                pats.push(p.as_bytes().to_vec());
                group_of.push(gi);
                pat_text.push(*p);
                pats.push(utf16le(p));
                group_of.push(gi);
                pat_text.push(*p);
            }
        }
        let groups = AhoCorasickBuilder::new().ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard).build(&pats).unwrap();
        let mut dp: Vec<Vec<u8>> = vec![];
        let mut dyn_api_of = vec![];
        for (i, a) in DYN_API_NAMES.iter().enumerate() {
            dp.push(a.as_bytes().to_vec());
            dyn_api_of.push(i);
            dp.push(utf16le(a));
            dyn_api_of.push(i);
        }
        let dyn_api = AhoCorasickBuilder::new().build(&dp).unwrap();
        StrMatchers { groups, group_of, pat_text, dyn_api, dyn_api_of }
    })
}

fn string_features(data: &[u8], imports: &[String], f: &mut Fv, findings: &mut Vec<Finding>) {
    let m = str_matchers();
    let mut counts = vec![0u32; STR_GROUPS.len()];
    let mut seen: Vec<HashSet<&'static str>> = vec![HashSet::new(); STR_GROUPS.len()];
    for mt in m.groups.find_overlapping_iter(data) {
        let pi = mt.pattern().as_usize();
        // Word boundaries: "frida" must not match "Friday". UTF-16 patterns are the odd indices.
        let step = if pi % 2 == 1 { 2 } else { 1 };
        let pat = m.pat_text[pi].as_bytes();
        let alnum = |o: Option<&u8>| o.map_or(false, |b| b.is_ascii_alphanumeric());
        let left_ok = !pat[0].is_ascii_alphanumeric() || mt.start() < step || !alnum(data.get(mt.start() - step));
        let right_ok = !pat[pat.len() - 1].is_ascii_alphanumeric() || !alnum(data.get(mt.end()));
        if !(left_ok && right_ok) {
            continue;
        }
        let gi = m.group_of[pi];
        counts[gi] += 1;
        if seen[gi].len() < 6 {
            seen[gi].insert(m.pat_text[mt.pattern().as_usize()]);
        }
    }
    for (gi, g) in STR_GROUPS.iter().enumerate() {
        // Distinct patterns matter more than repetitions; use distinct-ish count, capped.
        let distinct = seen[gi].len() as f32;
        f.set(g.feature, distinct + log2p(counts[gi] as f32) * 0.25);
        if seen[gi].is_empty() {
            continue;
        }
        let mut ev: Vec<&str> = seen[gi].iter().cloned().collect();
        ev.sort();
        let (cap, strength) = match g.feature {
            "str_vm_vendor" => ("anti_vm", 3),
            "str_vm_artifact" if distinct >= 5.0 => ("anti_vm", 2),
            "str_vm_artifact" => ("anti_vm", 1),
            "str_sandbox" if distinct >= 3.0 => ("anti_vm", 2),
            "str_dbg_tools" if distinct >= 2.0 => ("anti_debug", 2),
            "str_dbg_tools" => ("anti_debug", 1),
            "str_dbg_checks" => ("anti_debug", if ev.iter().any(|e| *e == "tracerpid") { 3 } else { 1 }),
            "str_net" if distinct >= 2.0 => ("network", 1),
            _ => continue,
        };
        findings.push(Finding { cap, rule: g.feature, strength, evidence: format!("strings: {}", ev.join(", ")) });
    }

    // Dynamic API resolution: API names present as strings but not imported.
    let imp: HashSet<&str> = imports.iter().map(|s| s.as_str()).collect();
    let mut dyn_names: HashSet<&str> = HashSet::new();
    for mt in m.dyn_api.find_iter(data) {
        let name = DYN_API_NAMES[m.dyn_api_of[mt.pattern().as_usize()]];
        // Require a terminator so "VirtualAllocEx" doesn't count as "VirtualAlloc".
        let end = mt.end();
        let term = data.get(end).map_or(true, |&b| b == 0 || !b.is_ascii_alphanumeric());
        if term && !imp.contains(name) {
            dyn_names.insert(name);
        }
    }
    f.set("dyn_api_strings", dyn_names.len() as f32);
    if dyn_names.len() >= 2 {
        let mut v: Vec<&str> = dyn_names.into_iter().collect();
        v.sort();
        v.truncate(8);
        findings.push(Finding { cap: "obfuscation", rule: "dynamic_api_names", strength: 1,
            evidence: format!("API names as strings, not imported: {}", v.join(", ")) });
    }

    // ASCII string statistics.
    let (mut n, mut total_len, mut rand, mut b64, mut hex, mut urls, mut ips, mut doms) = (0u32, 0u64, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32);
    let mut url_ex: Vec<String> = vec![];
    let mut start = None;
    let limit = data.len();
    for i in 0..=limit {
        let b = if i < limit { data[i] } else { 0 };
        let pr = (0x20..0x7f).contains(&b);
        match (pr, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= 5 {
                    let st = &data[s..i];
                    n += 1;
                    total_len += st.len() as u64;
                    classify_string(st, &mut rand, &mut b64, &mut hex, &mut urls, &mut ips, &mut doms, &mut url_ex);
                }
                start = None;
            }
            _ => {}
        }
    }
    f.set("strings_per_kb", n as f32 / (data.len() as f32 / 1024.0).max(1.0));
    f.set("str_mean_len", if n > 0 { total_len as f32 / n as f32 } else { 0.0 });
    f.set("rand_str_ratio", if n > 0 { rand as f32 / n as f32 } else { 0.0 });
    f.set("b64_strs", log2p(b64 as f32));
    f.set("hex_strs", log2p(hex as f32));
    f.set("urls", log2p(urls as f32));
    f.set("ipv4s", log2p(ips as f32));
    f.set("domains", log2p(doms as f32));
    if urls > 0 || ips > 0 {
        findings.push(Finding { cap: "network", rule: "hardcoded_endpoints", strength: 1,
            evidence: format!("{urls} URL(s), {ips} IPv4 literal(s){}", if url_ex.is_empty() { String::new() } else { format!(": {}", url_ex.join(" ")) }) });
    }
}

#[allow(clippy::too_many_arguments)]
fn classify_string(s: &[u8], rand: &mut u32, b64: &mut u32, hex: &mut u32, urls: &mut u32, ips: &mut u32, doms: &mut u32, url_ex: &mut Vec<String>) {
    let len = s.len();
    if len >= 12 && !s.contains(&b' ') {
        let e = shannon(s);
        let classes = [s.iter().any(u8::is_ascii_lowercase), s.iter().any(u8::is_ascii_uppercase), s.iter().any(u8::is_ascii_digit)]
            .iter().filter(|x| **x).count();
        if e > 3.8 && classes == 3 && e > (len as f32).log2() * 0.8 {
            *rand += 1;
        }
        if len >= 24 && classes == 3 && s.iter().all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(c)) {
            *b64 += 1;
        }
    }
    if len >= 32 && s.iter().all(u8::is_ascii_hexdigit) {
        *hex += 1;
    }
    for pref in [&b"http://"[..], &b"https://"[..]] {
        if let Some(p) = s.windows(pref.len()).position(|w| w.eq_ignore_ascii_case(pref)) {
            if s.len() > p + pref.len() + 3 {
                *urls += 1;
                if url_ex.len() < 3 {
                    let u = String::from_utf8_lossy(&s[p..s.len().min(p + 80)]).to_string();
                    url_ex.push(u);
                }
            }
        }
    }
    // IPv4 dotted quads (skip obvious version strings where all octets < 10).
    let mut i = 0;
    while i < len {
        if s[i].is_ascii_digit() && (i == 0 || !(s[i - 1].is_ascii_digit() || s[i - 1] == b'.')) {
            let mut j = i;
            let mut parts = 0;
            let mut big = false;
            let mut ok = true;
            loop {
                let st = j;
                while j < len && s[j].is_ascii_digit() {
                    j += 1;
                }
                if j == st || j - st > 3 {
                    ok = false;
                    break;
                }
                let v: u32 = std::str::from_utf8(&s[st..j]).unwrap().parse().unwrap();
                if v > 255 {
                    ok = false;
                    break;
                }
                big |= v >= 10;
                parts += 1;
                if parts == 4 || j >= len || s[j] != b'.' {
                    break;
                }
                j += 1;
            }
            let trailing_ok = j >= len || !(s[j].is_ascii_digit() || s[j] == b'.');
            if ok && parts == 4 && big && trailing_ok {
                *ips += 1;
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    const TLDS: &[&[u8]] = &[b".com", b".net", b".org", b".ru", b".cn", b".io", b".xyz", b".top", b".info", b".biz", b".onion", b".i2p", b".su", b".tk", b".cc", b".pw"];
    for t in TLDS {
        if len > t.len() + 2 {
            if let Some(p) = s.windows(t.len()).position(|w| w.eq_ignore_ascii_case(t)) {
                let after = s.get(p + t.len());
                if p > 1 && after.map_or(true, |c| !c.is_ascii_alphanumeric()) && s[p - 1].is_ascii_alphanumeric() {
                    *doms += 1;
                    break;
                }
            }
        }
    }
}

fn crypto_const_features(data: &[u8], f: &mut Fv, findings: &mut Vec<Finding>) {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    let ac = AC.get_or_init(|| AhoCorasick::new(CRYPTO_CONSTS.iter().map(|(_, p)| *p)).unwrap());
    let mut hit: Vec<&str> = vec![];
    for m in ac.find_iter(data) {
        let name = CRYPTO_CONSTS[m.pattern().as_usize()].0;
        if f.get(name) == 0.0 {
            hit.push(name);
        }
        f.set(name, 1.0);
    }
    let strong: Vec<&str> = hit.iter().filter(|h| !matches!(**h, "cc_base64" | "cc_crc32")).cloned().collect();
    if !strong.is_empty() {
        findings.push(Finding { cap: "crypto", rule: "crypto_constants", strength: 2,
            evidence: format!("constant tables: {}", strong.iter().map(|s| &s[3..]).collect::<Vec<_>>().join(", ")) });
    }
}

#[derive(Default)]
struct CodeStats {
    insn: u64,
    invalid: u64,
    bytes: u64,
    m: HashMap<&'static str, f32>,
    first: HashMap<&'static str, u64>,
}
impl CodeStats {
    fn hit(&mut self, k: &'static str, ip: u64) {
        *self.m.entry(k).or_insert(0.0) += 1.0;
        self.first.entry(k).or_insert(ip);
    }
    fn get(&self, k: &str) -> f32 {
        *self.m.get(k).unwrap_or(&0.0)
    }
}

fn imm_of(ins: &Instruction, op: u32) -> Option<u64> {
    match ins.op_kind(op) {
        OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate64
        | OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Some(ins.immediate(op)),
        _ => None,
    }
}

fn is_eax(r: Register) -> bool {
    matches!(r, Register::EAX | Register::RAX | Register::AX)
}

fn randomish(v: u32) -> bool {
    if v < 0x10000 {
        return false;
    }
    let pc = v.count_ones();
    // Reject round numbers / masks: needs varied nibbles.
    let nibbles: HashSet<u32> = (0..8).map(|i| (v >> (i * 4)) & 0xf).collect();
    (9..=23).contains(&pc) && nibbles.len() >= 5
}

const MAX_CODE: usize = 24 << 20;

fn code_features(data: &[u8], p: &Parsed, f: &mut Fv, findings: &mut Vec<Finding>) {
    let mut st = CodeStats::default();
    let mut budget = if p.x86 { MAX_CODE } else { 0 };
    for r in &p.code {
        if budget == 0 {
            break;
        }
        let len = r.len.min(budget);
        budget -= len;
        let bytes = &data[r.off..r.off + len];
        sweep(bytes, r.vaddr, p.bitness, &mut st);
    }
    if let (Some(eo), true) = (p.entry_off, p.x86) {
        if let Some(&b) = data.get(eo) {
            if b == 0x60 && p.bitness == 32 {
                f.set("entry_pushad", 1.0);
                findings.push(Finding { cap: "packed", rule: "entry_pushad", strength: 2,
                    evidence: "entry point starts with PUSHAD (classic packer stub)".into() });
            }
        }
    }
    let k = (st.insn as f32 / 1000.0).max(1.0);
    f.set("code_bytes_log2", log2p(st.bytes as f32));
    f.set("n_insn_log2", log2p(st.insn as f32));
    f.set("invalid_ratio", if st.insn > 0 { st.invalid as f32 / st.insn as f32 } else { 0.0 });
    for key in ["cpuid", "cpuid_hv_leaf", "cpuid_leaf1", "cpuid_hvbit", "rdtsc", "inline_int3", "int2d", "int_03",
        "icebp", "redpill", "io_port", "vmware_backdoor", "vmcall", "pushf_popf", "trap_flag", "peb_access",
        "kuser_shared", "raw_syscalls", "sys_ptrace", "sys_prctl", "sys_memfd", "sys_mprotect", "sys_execve",
        "sys_socket", "aesni", "sha_ni", "pclmul", "imm_tea", "imm_sha", "imm_md5", "imm_chacha", "imm_crc32",
        "imm_vm", "imm_apihash", "ror13", "rand_cmp", "stackstr_runs", "antidisasm_jcc", "call_next"] {
        f.set(key, log2p(st.get(key)));
    }
    for (key, src) in [("rot_rate", "rot"), ("xor_rate", "xor"), ("xor_imm_rate", "xor_imm"), ("call_reg_rate", "call_reg"),
        ("jmp_reg_rate", "jmp_reg"), ("rand_cmp_rate", "rand_cmp"), ("stackstr_dword_rate", "stackstr_dword"), ("ud2_rate", "ud2")] {
        f.set(key, st.get(src) / k);
    }

    let at = |k: &str| st.first.get(k).map(|a| format!(" (first at {a:#x})")).unwrap_or_default();
    let mut push = |cap, rule, strength, ev: String| findings.push(Finding { cap, rule, strength, evidence: ev });
    let c = |k: &str| st.get(k) as u32;
    if c("cpuid_hv_leaf") > 0 {
        push("anti_vm", "cpuid_hypervisor_leaf", 3, format!("CPUID leaf 0x4000000x queried {}x{}", c("cpuid_hv_leaf"), at("cpuid_hv_leaf")));
    }
    if c("cpuid_hvbit") > 0 {
        push("anti_vm", "cpuid_hypervisor_bit", 3, format!("CPUID.1 ECX[31] hypervisor bit tested{}", at("cpuid_hvbit")));
    }
    if c("vmware_backdoor") > 0 {
        push("anti_vm", "vmware_backdoor", 3, format!("IN from VMware backdoor port 0x5658{}", at("vmware_backdoor")));
    }
    if c("redpill") > 0 {
        push("anti_vm", "descriptor_table_probe", 2, format!("SIDT/SGDT/SLDT/STR/SMSW x{}{}", c("redpill"), at("redpill")));
    }
    if c("rdtsc") >= 2 {
        push("anti_debug", "rdtsc_timing", 1, format!("RDTSC x{}{} (timing checks)", c("rdtsc"), at("rdtsc")));
    }
    if c("inline_int3") > 0 {
        push("anti_debug", "inline_int3", 1, format!("INT3 inside code flow x{}{}", c("inline_int3"), at("inline_int3")));
    }
    if c("int2d") > 0 || c("icebp") > 0 {
        push("anti_debug", "int2d_icebp", 2, format!("INT 2D / ICEBP debugger traps{}{}", at("int2d"), at("icebp")));
    }
    if c("trap_flag") > 0 {
        push("anti_debug", "trap_flag", 2, format!("sets EFLAGS.TF via PUSHF/POPF{}", at("trap_flag")));
    }
    if c("peb_access") > 0 {
        push("anti_debug", "peb_access", 1, format!("reads PEB directly (fs:[30h]/gs:[60h]) x{}{}", c("peb_access"), at("peb_access")));
    }
    if c("kuser_shared") > 0 {
        push("anti_debug", "kuser_shared_data", 1, format!("reads KUSER_SHARED_DATA (0x7FFE0000){}", at("kuser_shared")));
    }
    if c("sys_ptrace") > 0 {
        push("anti_debug", "raw_ptrace_syscall", 2, format!("direct ptrace syscall{}", at("sys_ptrace")));
    }
    if c("sys_memfd") > 0 {
        push("packed", "raw_memfd_syscall", 2, format!("direct memfd_create/execveat syscall{}", at("sys_memfd")));
    }
    if c("aesni") > 0 || c("sha_ni") > 0 {
        push("crypto", "crypto_instructions", 2, format!("AES-NI x{} / SHA-NI x{}{}", c("aesni"), c("sha_ni"), at("aesni")));
    }
    let imm_crypto: Vec<&str> = ["imm_tea", "imm_sha", "imm_md5", "imm_chacha"].into_iter().filter(|k| c(k) > 0).collect();
    if !imm_crypto.is_empty() {
        push("crypto", "crypto_immediates", if imm_crypto.len() > 1 || c(imm_crypto[0]) > 2 { 2 } else { 1 },
            format!("crypto round constants in code: {}", imm_crypto.iter().map(|s| &s[4..]).collect::<Vec<_>>().join(", ")));
    }
    if c("stackstr_runs") >= 3 {
        push("obfuscation", "stack_strings", 1, format!("{} stack-built strings{}", c("stackstr_runs"), at("stackstr_runs")));
    }
    if c("antidisasm_jcc") > 0 {
        push("obfuscation", "anti_disassembly", 2, format!("complementary jcc pairs to one target x{}{}", c("antidisasm_jcc"), at("antidisasm_jcc")));
    }
    if c("ror13") >= 1 && c("call_reg") > 0 {
        push("obfuscation", "api_hashing", 1, format!("ROR 13 hashing loop{}", at("ror13")));
    }
    let rc = st.get("rand_cmp") / k;
    if st.get("rand_cmp") >= 8.0 && rc > 4.0 {
        push("obfuscation", "flattening_dispatch", 2, format!("{} compares against random 32-bit state constants ({rc:.1}/1k insn)", c("rand_cmp")));
    }
}

fn sweep(bytes: &[u8], vaddr: u64, bitness: u32, st: &mut CodeStats) {
    let mut dec = Decoder::with_ip(bitness, bytes, vaddr, DecoderOptions::NONE);
    let mut ins = Instruction::default();
    // Small history for context-sensitive patterns.
    let mut prev_m = Mnemonic::INVALID;
    let mut prev2_m = Mnemonic::INVALID;
    let mut prev_jcc: Option<(iced_x86::ConditionCode, u64)> = None;
    let mut eax_imm: Option<(u64, u64)> = None; // (value, insn index)
    let mut recent_imms: [u64; 8] = [u64::MAX; 8];
    let mut ri = 0usize;
    let mut cpuid_leaf1_at: Option<u64> = None;
    let mut pending_int3: Option<(Mnemonic, u64)> = None;
    let mut stack_run = 0u32;
    let mut pushf_at: Option<u64> = None;
    let mut idx: u64 = 0;
    // Rare instructions only count when the neighbourhood decodes like real code:
    // a candidate is dropped if another junk-class instruction sits within 8
    // instructions on either side (data embedded in .text decodes as such junk).
    const WIN: u64 = 8;
    let mut last_junk: u64 = 0;
    let mut pending: Vec<(&'static str, u64, u64)> = vec![]; // (key, ip, idx)
    st.bytes += bytes.len() as u64;
    while dec.can_decode() {
        dec.decode_out(&mut ins);
        idx += 1;
        st.insn += 1;
        let ip = ins.ip();
        // Commit candidates that have survived their trailing window.
        if !pending.is_empty() {
            let cut = idx.saturating_sub(WIN + 1);
            pending.retain(|(k, a, i)| if *i <= cut { st.hit(k, *a); false } else { true });
        }
        let clean_before = last_junk == 0 || idx - last_junk > WIN;
        if ins.is_invalid() || is_junk(&ins) {
            pending.retain(|(_, _, i)| *i + WIN < idx);
            last_junk = idx;
        }
        if ins.is_invalid() {
            st.invalid += 1;
            prev2_m = prev_m;
            prev_m = Mnemonic::INVALID;
            stack_run = 0;
            continue;
        }
        let m = ins.mnemonic();
        if let Some((before, at)) = pending_int3.take() {
            if m != Mnemonic::Int3 && !matches!(before, Mnemonic::Int3 | Mnemonic::Ret | Mnemonic::Jmp | Mnemonic::Nop | Mnemonic::INVALID | Mnemonic::Call | Mnemonic::Ud2) && m != Mnemonic::Nop {
                st.hit("inline_int3", at);
            }
        }
        // Immediates: crypto / VM / hashing constants.
        for op in 0..ins.op_count() {
            if let Some(v) = imm_of(&ins, op) {
                recent_imms[ri % 8] = v;
                ri += 1;
                let v32 = v as u32;
                if v32 as u64 == v || (v >> 32) == 0xffff_ffff {
                    for (c, kind) in CRYPTO_IMMS {
                        if *c == v32 {
                            let key = match *kind { "tea" => "imm_tea", "sha256" | "sha1" => "imm_sha", "md5" => "imm_md5", "chacha" => "imm_chacha", _ => "imm_crc32" };
                            st.hit(key, ip);
                        }
                    }
                    if VM_IMMS.iter().any(|(c, _)| *c == v32 && *c != 0x4000_0000 && *c > 0xffff) {
                        st.hit("imm_vm", ip);
                    }
                    if APIHASH_IMMS.contains(&v32) {
                        st.hit("imm_apihash", ip);
                    }
                    if (0x7FFE_0000..0x7FFE_1000).contains(&v32) {
                        st.hit("kuser_shared", ip);
                    }
                }
            }
        }
        if ins.op_count() >= 1 && ins.op_kind(0) == OpKind::Register && is_eax(ins.op_register(0)) {
            if m == Mnemonic::Mov {
                eax_imm = imm_of(&ins, 1).map(|v| (v, idx));
            } else if m == Mnemonic::Xor && ins.op_count() == 2 && ins.op_kind(1) == OpKind::Register && ins.op_register(1) == ins.op_register(0) {
                eax_imm = Some((0, idx));
            } else if m != Mnemonic::Cpuid {
                eax_imm = None;
            }
        }
        // Memory operand checks: PEB / KUSER_SHARED_DATA.
        for op in 0..ins.op_count() {
            if ins.op_kind(op) == OpKind::Memory {
                let seg = ins.memory_segment();
                let disp = ins.memory_displacement64();
                if (seg == Register::FS && disp == 0x30 && bitness == 32) || (seg == Register::GS && disp == 0x60 && bitness == 64) {
                    st.hit("peb_access", ip);
                }
                if ins.memory_base() == Register::None && (0x7FFE_0000..0x7FFE_1000).contains(&(disp as u32)) && disp >> 32 == 0 {
                    st.hit("kuser_shared", ip);
                }
            }
        }
        let recent = |v: u64| recent_imms.iter().any(|&x| x == v);
        macro_rules! cand {
            ($k:expr) => {
                if clean_before { pending.push(($k, ip, idx)); }
            };
        }
        match m {
            Mnemonic::Cpuid => {
                cand!("cpuid");
                if let Some((v, at)) = eax_imm {
                    if idx - at <= 6 {
                        if (0x4000_0000..=0x4000_00ff).contains(&v) {
                            st.hit("cpuid_hv_leaf", ip);
                        } else if v == 1 {
                            st.hit("cpuid_leaf1", ip);
                            cpuid_leaf1_at = Some(idx);
                        }
                    }
                }
            }
            Mnemonic::Bt | Mnemonic::Test | Mnemonic::And | Mnemonic::Shr => {
                if let Some(at) = cpuid_leaf1_at {
                    if idx - at <= 8 {
                        let is_hv = match m {
                            Mnemonic::Bt => imm_of(&ins, 1) == Some(31),
                            Mnemonic::Shr => imm_of(&ins, 1) == Some(31),
                            _ => imm_of(&ins, 1).map_or(false, |v| v as u32 == 0x8000_0000),
                        };
                        if is_hv {
                            st.hit("cpuid_hvbit", ip);
                            cpuid_leaf1_at = None;
                        }
                    } else {
                        cpuid_leaf1_at = None;
                    }
                }
            }
            Mnemonic::Rdtsc | Mnemonic::Rdtscp => cand!("rdtsc"),
            Mnemonic::Int3 => if clean_before { pending_int3 = Some((prev_m, ip)) },
            Mnemonic::Int => match imm_of(&ins, 0) {
                Some(0x2d) => cand!("int2d"),
                Some(0x03) => cand!("int_03"),
                Some(0x80) => {
                    st.hit("raw_syscalls", ip);
                    if let Some((v, at)) = eax_imm {
                        if idx - at <= 8 {
                            match v { 26 => st.hit("sys_ptrace", ip), 172 => st.hit("sys_prctl", ip), 356 | 358 => st.hit("sys_memfd", ip),
                                125 => st.hit("sys_mprotect", ip), 11 => st.hit("sys_execve", ip), 102 => st.hit("sys_socket", ip), _ => {} }
                        }
                    }
                }
                _ => {}
            },
            Mnemonic::Int1 => cand!("icebp"),
            Mnemonic::Sidt | Mnemonic::Sgdt | Mnemonic::Sldt | Mnemonic::Str | Mnemonic::Smsw => cand!("redpill"),
            Mnemonic::In | Mnemonic::Insd | Mnemonic::Insb => {
                cand!("io_port");
                if recent(0x5658) || recent(0x564D_5868) {
                    cand!("vmware_backdoor");
                }
            }
            Mnemonic::Out => cand!("io_port"),
            Mnemonic::Vmcall | Mnemonic::Vmmcall => cand!("vmcall"),
            Mnemonic::Pushfd | Mnemonic::Pushfq | Mnemonic::Pushf => pushf_at = Some(idx),
            Mnemonic::Popfd | Mnemonic::Popfq | Mnemonic::Popf => {
                if let Some(at) = pushf_at {
                    if idx - at <= 4 {
                        st.hit("pushf_popf", ip);
                        if recent(0x100) {
                            st.hit("trap_flag", ip);
                        }
                    }
                }
            }
            Mnemonic::Syscall | Mnemonic::Sysenter => {
                st.hit("raw_syscalls", ip);
                if let Some((v, at)) = eax_imm {
                    if idx - at <= 8 && bitness == 64 {
                        match v { 101 => st.hit("sys_ptrace", ip), 157 => st.hit("sys_prctl", ip), 319 | 322 => st.hit("sys_memfd", ip),
                            10 => st.hit("sys_mprotect", ip), 59 => st.hit("sys_execve", ip), 41 | 42 => st.hit("sys_socket", ip), _ => {} }
                    }
                }
            }
            Mnemonic::Aesenc | Mnemonic::Aesenclast | Mnemonic::Aesdec | Mnemonic::Aesdeclast | Mnemonic::Aeskeygenassist
            | Mnemonic::Aesimc | Mnemonic::Vaesenc | Mnemonic::Vaesenclast | Mnemonic::Vaesdec | Mnemonic::Vaesdeclast => st.hit("aesni", ip),
            Mnemonic::Sha256rnds2 | Mnemonic::Sha256msg1 | Mnemonic::Sha1rnds4 | Mnemonic::Sha1msg1 => st.hit("sha_ni", ip),
            Mnemonic::Pclmulqdq | Mnemonic::Vpclmulqdq => st.hit("pclmul", ip),
            Mnemonic::Rol | Mnemonic::Ror => {
                st.hit("rot", ip);
                if m == Mnemonic::Ror && imm_of(&ins, 1) == Some(13) {
                    st.hit("ror13", ip);
                }
            }
            Mnemonic::Xor | Mnemonic::Pxor | Mnemonic::Vpxor | Mnemonic::Xorps => {
                let same = ins.op_count() == 2 && ins.op_kind(0) == OpKind::Register && ins.op_kind(1) == OpKind::Register
                    && ins.op_register(0) == ins.op_register(1);
                if !same {
                    st.hit("xor", ip);
                    if imm_of(&ins, 1).is_some() {
                        st.hit("xor_imm", ip);
                    }
                }
            }
            Mnemonic::Call => {
                match ins.op_kind(0) {
                    OpKind::Register => st.hit("call_reg", ip),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                        if ins.near_branch_target() == ins.next_ip() {
                            st.hit("call_next", ip);
                        }
                    }
                    _ => {}
                }
            }
            Mnemonic::Jmp => {
                if ins.op_kind(0) == OpKind::Register {
                    st.hit("jmp_reg", ip);
                }
            }
            Mnemonic::Cmp | Mnemonic::Sub => {
                if let Some(v) = imm_of(&ins, 1) {
                    if (v as u32 as u64 == v || v >> 32 == 0xffff_ffff) && randomish(v as u32) {
                        st.hit("rand_cmp", ip);
                    }
                }
            }
            Mnemonic::Ud2 => st.hit("ud2", ip),
            _ => {}
        }
        // Anti-disassembly: jz X ; jnz X (complementary conditions, same target).
        let cc = ins.condition_code();
        let is_jcc = cc != iced_x86::ConditionCode::None && matches!(ins.op_kind(0), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)
            && m != Mnemonic::Cmovne && !matches!(m, Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne | Mnemonic::Jrcxz | Mnemonic::Jecxz);
        if is_jcc {
            let t = ins.near_branch_target();
            if let Some((pcc, pt)) = prev_jcc {
                if pt == t && negate(pcc) == cc {
                    st.hit("antidisasm_jcc", ip);
                }
            }
            prev_jcc = Some((cc, t));
        } else {
            prev_jcc = None;
        }
        // Stack strings: runs of byte stores of printable immediates to memory.
        if m == Mnemonic::Mov && ins.op_count() == 2 && ins.op_kind(0) == OpKind::Memory {
            match ins.op_kind(1) {
                OpKind::Immediate8 => {
                    let v = ins.immediate(1) as u8;
                    if (0x20..0x7f).contains(&v) || v == 0 {
                        stack_run += 1;
                        if stack_run == 4 {
                            st.hit("stackstr_runs", ip);
                        }
                    } else {
                        stack_run = 0;
                    }
                }
                OpKind::Immediate32 | OpKind::Immediate32to64 => {
                    let v = ins.immediate(1) as u32;
                    if v.to_le_bytes().iter().all(|b| (0x20..0x7f).contains(b)) {
                        st.hit("stackstr_dword", ip);
                    }
                    stack_run = 0;
                }
                _ => stack_run = 0,
            }
        } else if m != Mnemonic::Nop {
            stack_run = 0;
        }
        prev2_m = prev_m;
        prev_m = m;
    }
    for (k, a, _) in pending {
        st.hit(k, a);
    }
    let _ = prev2_m;
}

/// Instructions that are rare in compiler output but common when data is
/// decoded as code. Used to discount rare-instruction hits in junk regions.
fn is_junk(ins: &Instruction) -> bool {
    use Mnemonic::*;
    matches!(ins.mnemonic(), In | Out | Insb | Insw | Insd | Outsb | Outsw | Outsd | Int1 | Hlt | Cli | Sti
        | Sidt | Sgdt | Sldt | Str | Smsw | Lidt | Lgdt | Lldt | Ltr | Arpl | Bound | Les | Lds | Lss | Lfs | Lgs
        | Iret | Iretd | Iretq | Into | Aaa | Aas | Daa | Das | Aam | Aad | Salc | Xlatb | Retf | Wait | Cmc
        | Clts | Invd | Wbinvd | Rsm | Sysexit | Sysret | Lar | Lsl | Verr | Verw | Pushad | Popad
        | Fnstenv | Fnsave | Frstor | Fldenv | Fbld | Fbstp | Fisttp | Enter | Std | Loopne | Loope | Jrcxz | Jecxz)
        || (ins.mnemonic() == Int && !matches!(ins.immediate(0), 0x03 | 0x80 | 0x29 | 0x2c | 0x2d | 0x2e))
        || ((ins.mnemonic() == Jmp || ins.mnemonic() == Call) && matches!(ins.op_kind(0), OpKind::FarBranch16 | OpKind::FarBranch32))
        || (ins.mnemonic() == Mov && ins.op_count() == 2 && ins.op_kind(0) == OpKind::Register && ins.op_register(0).is_segment_register())
}

fn negate(cc: iced_x86::ConditionCode) -> iced_x86::ConditionCode {
    use iced_x86::ConditionCode::*;
    match cc {
        o => no, no => o, b => ae, ae => b, e => ne, ne => e, be => a, a => be,
        s => ns, ns => s, p => np, np => p, l => ge, ge => l, le => g, g => le, None => None,
    }
}

/// Rules that need several features together.
fn derived_rules(f: &Fv, findings: &mut Vec<Finding>) {
    let size = 2f32.powf(f.get("size_log2")) - 1.0;
    let few = f.get("n_imports_log") <= log2p(8.0) && f.get("is_static") == 0.0 && f.get("is_dotnet") == 0.0 && f.get("fmt_pe") == 1.0;
    if few && size > 32.0 * 1024.0 {
        findings.push(Finding { cap: "packed", rule: "tiny_import_table", strength: 1,
            evidence: format!("{} imports in a {:.0} KiB PE", (2f32.powf(f.get("n_imports_log")) - 1.0).round(), size / 1024.0) });
    }
    if f.get("exec_entropy_max") > 7.0 {
        findings.push(Finding { cap: "packed", rule: "high_entropy_code", strength: 2,
            evidence: format!("executable section entropy {:.2} bits/byte", f.get("exec_entropy_max")) });
    }
    if f.get("overlay_ratio") > 0.3 && f.get("overlay_entropy") > 7.5 {
        findings.push(Finding { cap: "packed", rule: "encrypted_overlay", strength: 1,
            evidence: format!("{:.0}% of file is a high-entropy overlay ({:.2})", f.get("overlay_ratio") * 100.0, f.get("overlay_entropy")) });
    }
    if f.get("rsrc_ratio") > 0.3 && f.get("rsrc_entropy") > 7.5 {
        findings.push(Finding { cap: "packed", rule: "encrypted_resources", strength: 1,
            evidence: format!("{:.0}% of file is high-entropy resources", f.get("rsrc_ratio") * 100.0) });
    }
    if f.get("data_entropy_max") > 7.5 && f.get("frac_high_win") > 0.25 {
        findings.push(Finding { cap: "packed", rule: "high_entropy_data", strength: 1,
            evidence: format!("data section entropy {:.2}, {:.0}% of file high-entropy", f.get("data_entropy_max"), f.get("frac_high_win") * 100.0) });
    }
    if f.get("upx_marker") > 0.0 {
        findings.push(Finding { cap: "packed", rule: "upx", strength: 3, evidence: "UPX! marker".into() });
    }
    if f.get("invalid_ratio") > 0.05 && f.get("n_insn_log2") > 8.0 {
        findings.push(Finding { cap: "packed", rule: "undecodable_code", strength: 2,
            evidence: format!("{:.0}% of executable bytes don't decode as x86", f.get("invalid_ratio") * 100.0) });
    }
}
