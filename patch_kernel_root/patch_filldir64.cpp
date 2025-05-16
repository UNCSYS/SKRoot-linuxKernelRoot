#include "patch_filldir64.h"
#include "analyze/ARM_asm.h"
PatchFilldir64::PatchFilldir64(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
	const AnalyzeKernel& analyze_kernel) : m_file_buf(file_buf), m_sym(sym), m_analyze_kernel(analyze_kernel) {

}

PatchFilldir64::~PatchFilldir64()
{
}

int PatchFilldir64::get_atomic_usage_len() {
	int len = 8;
	if (m_analyze_kernel.is_kernel_version_less("6.6.0")) {
		len = 4;
	}
	return len;
}

size_t PatchFilldir64::patch_filldir64(size_t root_key_addr_offset, size_t hook_func_start_addr, const std::vector<size_t>& task_struct_offset_cred, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t filldir64_addr = m_sym.filldir64;
	int atomic_usage_len = get_atomic_usage_len();

	int root_key_adr_offset = root_key_addr_offset - (hook_func_start_addr + 4 * 4);

	size_t filldir64_entry_hook_jump_back_addr = filldir64_addr + 4;
	auto next_asm_line_bytes_cnt = (task_struct_offset_cred.size() - 1) * 4;
	std::stringstream sstrAsm;
	sstrAsm
		<< "CMP W2, #16" << std::endl
		<< "BNE #" << 92 + next_asm_line_bytes_cnt << std::endl
		<< "STP X7, X8, [sp, #-16]!" << std::endl
		<< "STP X9, X10, [sp, #-16]!" << std::endl
		<< "ADR X7, #"<< root_key_adr_offset << std::endl
		<< "MOV X8, #0" << std::endl
		<< "LDRB W9, [X1, X8]" << std::endl
		<< "LDRB W10, [X7, X8]" << std::endl
		<< "CMP W9, W10" << std::endl
		<< "B.NE #" << 52 + next_asm_line_bytes_cnt << std::endl
		<< "ADD X8, X8, 1" << std::endl
		<< "CMP X8, #16" << std::endl
		<< "BLT #-24" << std::endl;
		sstrAsm << "MRS X7, SP_EL0" << std::endl;
		for (auto x = 0; x < task_struct_offset_cred.size(); x++) {
			if (x != task_struct_offset_cred.size() - 1) {
				sstrAsm << "LDR X7, [X7, #" << task_struct_offset_cred[x] << "]" << std::endl;
			}
		}
		sstrAsm << "LDR X7, [X7, #" << task_struct_offset_cred[task_struct_offset_cred.size() - 1] << "]" << std::endl
		<< "CBZ X7, #" << 28 << std::endl
		<< "ADD X7, X7, #"<< atomic_usage_len << std::endl
		<< "MOV X8, #8" << std::endl
		<< "LDR  W9, [X7], #4" << std::endl
		<< "CBNZ  W9, #" << 88 << std::endl
		<< "SUBS  X8, X8, #1" << std::endl
		<< "B.NE #-" << 12 << std::endl
		<< "LDP X9, X10, [sp], #16" << std::endl
		<< "LDP X7, X8, [sp], #16" << std::endl
		<< "MOV X0, X0" << std::endl
		<< "B #" << filldir64_entry_hook_jump_back_addr - (hook_func_start_addr + 0x64 + next_asm_line_bytes_cnt) << std::endl;

	std::string strAsmCode = sstrAsm.str();
	std::cout << std::endl << strAsmCode << std::endl;

	std::string strBytes = AsmToBytes(strAsmCode);
	if (!strBytes.length()) {
		return 0;
	}
	size_t nHookFuncSize = strBytes.length() / 2;

	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)&m_file_buf[0] + filldir64_addr), sizeof(hookOrigCmd));
	std::string strHookOrigCmd = bytes_2_hex_str((const unsigned char*)hookOrigCmd, sizeof(hookOrigCmd));
	strBytes = strBytes.substr(0, (0x60 + next_asm_line_bytes_cnt) * 2) + strHookOrigCmd + strBytes.substr((0x60 + next_asm_line_bytes_cnt + 4) * 2);

	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });
	std::stringstream sstrAsm2;
	sstrAsm2
		<< "B #" << hook_func_start_addr - filldir64_addr << std::endl;
	std::string strBytes2 = AsmToBytes(sstrAsm2.str());
	if (!strBytes2.length()) {
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ strBytes2, filldir64_addr });
	hook_func_start_addr += nHookFuncSize;
	std::cout << "#下一段HOOK函数起始可写位置：" << std::hex << hook_func_start_addr << std::endl << std::endl;
	return hook_func_start_addr + nHookFuncSize;
}
