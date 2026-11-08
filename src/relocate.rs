use crate::asm::arm64asm;
use crate::result::{WispError, WispResult};
use dynasmrt::aarch64::Assembler;
use exarmo_aarch64::{self as exarmo, BranchKind, Instruction, Mnemonic, Operand};

const IP_REGISTER: u8 = 17;

/// Emits the single displaced instruction; the caller appends the normal resume jump.
#[allow(clippy::useless_conversion)] // dynasm inserts Into<u8> for dynamic register IDs.
pub(crate) fn emit(ops: &mut Assembler, insn: u32, from: usize) -> WispResult<()> {
    let unsupported = || WispError::NotSupported {
        instruction: insn,
        offset: 0,
    };
    let instruction = exarmo::decode_word(insn).map_err(|_| unsupported())?;

    if instruction.unpredictable() {
        return Err(unsupported());
    }

    let address = |offset: i64| (from as u64).wrapping_add_signed(offset);

    match instruction {
        Instruction::AdrOnlyPcreladdr {
            Xd: register,
            offset,
        } => {
            load_address(ops, register.num(), address(offset.into()));
        }
        Instruction::AdrpOnlyPcreladdr {
            Xd: register,
            offset,
        } => {
            load_address(
                ops,
                register.num(),
                ((from as u64) & !0xfff).wrapping_add_signed(offset),
            );
        }
        Instruction::BOnlyBranchImm { offset } => {
            if offset == 0 {
                // Loop on the relocated instruction, bypassing the installed hook.
                arm64asm!(ops; b 0);
            } else {
                load_address(ops, IP_REGISTER, address(offset.into()));
                // Original direct-branch destinations need not be BTI landing pads.
                arm64asm!(ops; ret ip);
            }
        }
        Instruction::Ldr32Loadlit {
            Wt: register,
            offset,
        } => {
            literal_address(ops, address(offset.into()), from, 4).map_err(|_| unsupported())?;
            arm64asm!(ops; ldr W(register.num()), [ip]);
        }
        Instruction::Ldr64Loadlit {
            Xt: register,
            offset,
        } => {
            literal_address(ops, address(offset.into()), from, 8).map_err(|_| unsupported())?;
            arm64asm!(ops; ldr X(register.num()), [ip]);
        }
        Instruction::Ldrsw64Loadlit {
            Xt: register,
            offset,
        } => {
            literal_address(ops, address(offset.into()), from, 4).map_err(|_| unsupported())?;
            arm64asm!(ops; ldrsw X(register.num()), [ip]);
        }
        _ if is_unsupported(&instruction) => return Err(unsupported()),
        _ => ops.extend(insn.to_le_bytes()),
    }

    Ok(())
}

#[allow(clippy::useless_conversion)] // dynasm inserts Into<u8> for dynamic register IDs.
fn load_address(ops: &mut Assembler, register: u8, value: u64) {
    arm64asm!(ops
        ; movz X(register), (value & 0xffff) as u32
        ; movk X(register), ((value >> 16) & 0xffff) as u32, lsl #16
        ; movk X(register), ((value >> 32) & 0xffff) as u32, lsl #32
        ; movk X(register), ((value >> 48) & 0xffff) as u32, lsl #48
    );
}

fn literal_address(ops: &mut Assembler, address: u64, from: usize, size: u64) -> Result<(), ()> {
    // Reading overwritten code as data requires a separate preservation policy.
    if address <= from as u64 && (from as u64) - address < size {
        return Err(());
    }

    load_address(ops, IP_REGISTER, address);

    Ok(())
}

fn is_unsupported(instruction: &Instruction) -> bool {
    // These PAC forms use or pair with a PC modifier without necessarily exposing a label.
    matches!(
        instruction.mnemonic(),
        Mnemonic::Paciasppc
            | Mnemonic::Pacibsppc
            | Mnemonic::Autiasppc
            | Mnemonic::Autibsppc
            | Mnemonic::Autiasppcr
            | Mnemonic::Autibsppcr
            | Mnemonic::Retaasppc
            | Mnemonic::Retabsppc
            | Mnemonic::Retaasppcr
            | Mnemonic::Retabsppcr
    ) || !matches!(
        instruction.branch().kind,
        BranchKind::None | BranchKind::Indirect | BranchKind::Return
    ) || instruction
        .operands()
        .as_slice()
        .iter()
        .any(|operand| matches!(operand, Operand::Label { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asm::Assemble;
    use crate::{Wisp, orig_fn};
    use core::arch::naked_asm;
    use dynasmrt::{AssemblyOffset, DynasmApi, ExecutableBuffer};
    use std::ffi::c_void;
    use std::{hint, mem};

    type Function = unsafe extern "C" fn(u64, u64) -> u64;

    extern "C" fn proxy(a: u64, b: u64) -> u64 {
        let original = unsafe { orig_fn!(Function) };
        unsafe { original(a, b) }
    }

    fn check_relocated_calls(ops: Assembler, entry: AssemblyOffset, args: (u64, u64)) -> u64 {
        let buffer = ops.assemble().unwrap();
        let target = buffer.ptr(entry).cast::<c_void>();
        let call: Function = unsafe { mem::transmute(target) };
        let expected = unsafe { call(args.0, args.1) };
        let stub = unsafe { Wisp::hook_fn(target, proxy as _, None).unwrap() };
        let actual = unsafe { hint::black_box(call)(args.0, args.1) };
        unsafe { stub.unhook().unwrap() };
        assert_eq!(actual, expected);
        assert_eq!(unsafe { hint::black_box(call)(args.0, args.1) }, expected);

        extern "C" fn callback(_: *mut libc::c_long) {}

        let stub = unsafe { Wisp::intercept_fn(target, callback).unwrap() };
        let actual = unsafe { hint::black_box(call)(args.0, args.1) };
        unsafe { stub.unhook().unwrap() };
        assert_eq!(actual, expected, "intercept relocation");
        assert_eq!(unsafe { hint::black_box(call)(args.0, args.1) }, expected);
        expected
    }

    #[test]
    fn adr_keeps_original_pc_and_boundary_offsets() {
        for offset in [-(1i32 << 20), -1, 0, 1, (1 << 20) - 1] {
            let mut ops = Assembler::new().unwrap();
            arm64asm!(ops; adr x0, offset; ret);
            check_relocated_calls(ops, AssemblyOffset(0), (0, 0));
        }
    }

    #[test]
    fn adrp_keeps_original_page_and_boundary_offsets() {
        for offset in [i32::MIN, -0x1000, 0, 0x1000, i32::MAX - 0xfff] {
            let mut ops = Assembler::new().unwrap();
            arm64asm!(ops; adrp x0, offset; ret);
            check_relocated_calls(ops, AssemblyOffset(0), (0, 0));
        }
    }

    #[test]
    fn integer_literals_keep_data_addresses() {
        for before in [false, true] {
            for kind in 0..3 {
                let mut ops = Assembler::new().unwrap();
                let data = ops.new_dynamic_label();
                if before {
                    arm64asm!(ops; =>data);
                    ops.push_u64(0xffffffff87654321);
                }
                let entry = ops.offset();
                match kind {
                    0 => arm64asm!(ops; ldr w0, =>data),
                    1 => arm64asm!(ops; ldr x0, =>data),
                    _ => arm64asm!(ops; ldrsw x0, =>data),
                }
                arm64asm!(ops; ret);
                if !before {
                    arm64asm!(ops; =>data);
                    ops.push_u64(0xffffffff87654321);
                }
                let result = check_relocated_calls(ops, entry, (73, 0));
                let expected = match kind {
                    0 => 0x87654321,
                    _ => 0xffffffff87654321,
                };
                assert_eq!(result, expected);
            }
        }
    }

    #[test]
    fn unconditional_branches_keep_forward_and_backward_targets() {
        for before in [false, true] {
            let mut ops = Assembler::new().unwrap();
            let taken = ops.new_dynamic_label();
            if before {
                arm64asm!(ops; =>taken; add x0, x0, #19; ret);
            }
            let entry = ops.offset();
            arm64asm!(ops; b =>taken; brk #0);
            if !before {
                arm64asm!(ops; =>taken; add x0, x0, #19; ret);
            }
            assert_eq!(check_relocated_calls(ops, entry, (4, 0)), 23);
        }
    }

    fn relocated_insn(insn: u32, from: usize) -> ExecutableBuffer {
        let mut ops = Assembler::new().unwrap();
        emit(&mut ops, insn, from).unwrap();
        arm64asm!(ops; mov x0, #37; ret);
        ops.assemble().unwrap()
    }

    #[test]
    fn adrp_supports_full_signed_displacements() {
        // Fixture words assembled independently with the Android NDK's LLVM assembler.
        for insn in [0x90800000u32, 0xf07fffe0] {
            let mut ops = Assembler::new().unwrap();
            ops.push_u32(insn);
            arm64asm!(ops; ret);
            check_relocated_calls(ops, AssemblyOffset(0), (0, 0));
        }
    }

    #[test]
    fn branches_support_full_signed_displacements() {
        let mut ops = Assembler::new().unwrap();
        arm64asm!(ops; mov x0, #91; ret);
        let taken = ops.assemble().unwrap();
        for (insn, offset) in [(0x16000000, -(1i64 << 27)), (0x15ffffff, (1 << 27) - 4)] {
            let from = (taken.as_ptr() as usize).wrapping_add_signed(-(offset as isize));
            let code = relocated_insn(insn, from);
            let call: Function = unsafe { mem::transmute(code.as_ptr()) };
            assert_eq!(unsafe { call(0, 0) }, 91);
        }
    }

    #[test]
    fn literal_boundaries_read_live_memory_without_copying_data() {
        let mut data = [0xffffffff87654321u64];
        // The two instructions in each pair are the negative and positive literal displacement limits.
        for (kind, insns) in [
            [0x18800000, 0x187fffe0],
            [0x58800000, 0x587fffe0],
            [0x98800000, 0x987fffe0],
        ]
        .into_iter()
        .enumerate()
        {
            for (insn, offset) in insns.into_iter().zip([-(1i64 << 20), (1 << 20) - 4]) {
                let from = (data.as_ptr() as usize).wrapping_add_signed(-(offset as isize));
                let mut ops = Assembler::new().unwrap();
                emit(&mut ops, insn, from).unwrap();
                arm64asm!(ops; ret);
                let code = ops.assemble().unwrap();
                let call: Function = unsafe { mem::transmute(code.as_ptr()) };
                let expected = match kind {
                    0 => 0x87654321,
                    _ => 0xffffffff87654321,
                };
                assert_eq!(unsafe { call(0, 0) }, expected);
                // The relocated load must follow later data changes, not an installation snapshot.
                unsafe {
                    data.as_mut_ptr().write_volatile(0x12345678);
                }
                assert_eq!(unsafe { call(0, 0) }, 0x12345678);
                data = [0xffffffff87654321];
            }
        }
    }

    #[test]
    fn self_branches_target_the_relocated_instruction() {
        let code = relocated_insn(0x14000000, 0x12340000);
        assert!(matches!(
            exarmo::decode_word(u32::from_le_bytes(code[..4].try_into().unwrap())),
            Ok(Instruction::BOnlyBranchImm { offset: 0 })
        ));
    }

    #[test]
    fn paciasp_keeps_sign_and_authentication_paired() {
        #[unsafe(naked)]
        unsafe extern "C" fn target(_: u64, _: u64) -> u64 {
            naked_asm!(
                "paciasp",
                "stp x29, x30, [sp, #-16]!",
                "add x0, x0, #3",
                "ldp x29, x30, [sp], #16",
                "autiasp",
                "ret"
            );
        }
        let call = hint::black_box(target as Function);
        let stub = unsafe { Wisp::hook_fn(target as _, proxy as _, None).unwrap() };
        assert_eq!(unsafe { call(8, 0) }, 11);
        unsafe { stub.unhook().unwrap() };
        extern "C" fn callback(args: *mut libc::c_long) {
            unsafe {
                *args = 20;
            }
        }
        let stub = unsafe { Wisp::intercept_fn(target as _, callback).unwrap() };
        assert_eq!(unsafe { call(8, 0) }, 23);
        unsafe { stub.unhook().unwrap() };
    }

    #[test]
    fn intercept_relocates_with_callback_modified_arguments() {
        let mut ops = Assembler::new().unwrap();
        arm64asm!(ops; adr x1, >value; ldr x1, [x1]; add x0, x0, x1; ret; value:);
        ops.push_u64(17);
        let target = ops.assemble().unwrap();
        extern "C" fn callback(args: *mut libc::c_long) {
            unsafe {
                *args = 100;
            }
        }
        let call: Function = unsafe { mem::transmute(target.as_ptr()) };
        let stub = unsafe { Wisp::intercept_fn(target.as_ptr().cast(), callback).unwrap() };
        assert_eq!(unsafe { call(1, 0) }, 117);
        unsafe { stub.unhook().unwrap() };
    }

    #[test]
    fn acquire_load_preserves_behavior() {
        let value = 19u64;
        let mut ops = Assembler::new().unwrap();
        arm64asm!(ops; ldar x0, [x0]; ret);
        assert_eq!(
            check_relocated_calls(ops, AssemblyOffset(0), (&value as *const u64 as u64, 0)),
            value
        );
    }

    #[test]
    fn ordinary_instructions_are_copied_unchanged() {
        let mut ops = Assembler::new().unwrap();
        arm64asm!(ops; nop; stp fp, lr, [sp, #-16]!; sub sp, sp, #16; fabs d0, d0; ret);
        let source = ops.assemble().unwrap();
        for bytes in source.chunks_exact(4) {
            let mut ops = Assembler::new().unwrap();
            emit(
                &mut ops,
                u32::from_le_bytes(bytes.try_into().unwrap()),
                source.as_ptr() as usize,
            )
            .unwrap();
            assert_eq!(&ops.assemble().unwrap()[..], bytes);
        }
    }

    #[test]
    fn literal_reads_reject_partial_overlap_but_allow_adjacent_data() {
        for (opcode, size) in [(0x18000000u32, 4), (0x58000000, 8), (0x98000000, 4)] {
            for offset in [-8i32, -4, 0, 4] {
                let insn = opcode | (((offset / 4) as u32 & 0x7ffff) << 5);
                let mut ops = Assembler::new().unwrap();
                let result = emit(&mut ops, insn, 0x1000);
                let overlaps = offset == 0 || (size == 8 && offset == -4);
                if overlaps {
                    assert!(matches!(result, Err(WispError::NotSupported { .. })));
                } else {
                    result.unwrap();
                }
            }
        }
    }

    #[test]
    fn rejects_unsupported_pc_relative_and_control_flow_instructions() {
        for insn in [
            0x94000001, // BL
            0xd63f0000, // BLR X0
            0x54000020, // B.EQ
            0xb4000020, 0x35000020, // CBZ / CBNZ
            0x36000020, 0x37000020, // TBZ / TBNZ
            0x1c000020, 0x5c000020, 0x9c000020, // SIMD literal LDR
            0xd8000020, // Literal PRFM
            0xd4000001, // SVC
        ] {
            let mut ops = Assembler::new().unwrap();
            assert!(
                matches!(emit(&mut ops, insn, 0x1234), Err(WispError::NotSupported { instruction, offset: 0 }) if instruction == insn),
                "instruction {insn:#010x}"
            );
        }
    }

    #[test]
    fn rejects_pc_diversified_pac() {
        // PACIASPPC uses PC as an implicit signing modifier; unlike PACIASP it cannot be copied.
        let mut ops = Assembler::new().unwrap();
        let insn = 0xdac1a3fe;
        assert!(matches!(
            exarmo::decode_word(insn),
            Ok(Instruction::Paciasppc64lrDp1src)
        ));
        assert!(matches!(
            emit(&mut ops, insn, 0x1234),
            Err(WispError::NotSupported { .. })
        ));
    }

    #[test]
    fn rejects_invalid_and_unpredictable_encodings() {
        for insn in [0xffffffff, 0x1920b3e0, 0xd478da60] {
            let mut ops = Assembler::new().unwrap();
            assert!(
                matches!(emit(&mut ops, insn, 0x1234), Err(WispError::NotSupported { instruction, offset: 0 }) if instruction == insn),
                "instruction {insn:#010x}"
            );
        }
    }

    #[test]
    fn relocated_target_can_be_hooked_and_unhooked_repeatedly() {
        let mut ops = Assembler::new().unwrap();
        arm64asm!(ops; adr x0, >value; ldr x0, [x0]; ret; value:);
        ops.push_u64(91);
        let buffer = ops.assemble().unwrap();
        let target = buffer.as_ptr().cast::<c_void>();
        let call: Function = unsafe { mem::transmute(target) };
        for _ in 0..8 {
            let stub = unsafe { Wisp::hook_fn(target, proxy as _, None).unwrap() };
            assert_eq!(unsafe { hint::black_box(call)(0, 0) }, 91);
            unsafe { stub.unhook().unwrap() };
            assert_eq!(unsafe { hint::black_box(call)(0, 0) }, 91);
        }
    }
}
