#include "patch_avc_denied.h"
#include "analyze/ARM_asm.h"
PatchAvcDenied::PatchAvcDenied(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
	const SymbolAnalyze& symbol_analyze) : PatchBase(file_buf, sym, symbol_analyze) {

}

PatchAvcDenied::~PatchAvcDenied()
{
}

int PatchAvcDenied::get_need_read_cap_cnt() {
	int cnt = get_cap_cnt();
	if (cnt < 5) {
		cnt = 3;
	}
	return cnt;
}


size_t PatchAvcDenied::patch_avc_denied(size_t hook_func_start_addr, const std::vector<size_t>& task_struct_offset_cred,
	std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t avc_denied_addr = m_sym.avc_denied;
	int atomic_usage_len = get_cred_atomic_usage_len();
	int securebits_padding = get_cred_securebits_padding();
	std::string cap_ability_max = get_cap_ability_max();
	int cap_cnt = get_need_read_cap_cnt();

	size_t avc_denied_entry_hook_jump_back_addr = avc_denied_addr + 4;
	auto next_asm_line_bytes_cnt = (task_struct_offset_cred.size() - 1) * 4;
	std::stringstream sstrAsm;
	sstrAsm
		<< "STP X7, X8, [sp, #-16]!" << std::endl
		<< "STP X9, X10, [sp, #-16]!" << std::endl;
	sstrAsm << "MRS X7, SP_EL0" << std::endl;
	for (auto x = 0; x < task_struct_offset_cred.size(); x++) {
		if (x != task_struct_offset_cred.size() - 1) {
			sstrAsm << "LDR X7, [X7, #" << task_struct_offset_cred[x] << "]" << std::endl;
		}
	}

	sstrAsm << "LDR X7, [X7, #" << task_struct_offset_cred[task_struct_offset_cred.size() - 1] << "]" << std::endl
		<< "CBZ X7, #" << 88 << std::endl
		<< "ADD X7, X7, #"<< atomic_usage_len << std::endl
		<< "MOV X8, #8" << std::endl
		<< "LDR  W9, [X7], #4" << std::endl
		<< "CBNZ  W9, #" << 72 << std::endl
		<< "SUBS  X8, X8, #1" << std::endl
		<< "B.NE #-" << 12 << std::endl
		<< "MOV W8, 0xC" << std::endl
		<< "LDR  W9, [X7], #"<< 4 + securebits_padding << std::endl
		<< "CMP W8, W9" << std::endl
		<< "B.NE #" << 48 << std::endl
		<< "MOV X8, "<< cap_ability_max << std::endl
		<< "MOV X9, #"<< cap_cnt << std::endl
		<< "LDR X10, [X7], #8" << std::endl
		<< "CMP X10, X8" << std::endl
		<< "B.CC #" << 28 << std::endl
		<< "SUBS  X9, X9, #1" << std::endl
		<< "B.NE #-16" << std::endl
		<< "LDP X9, X10, [sp], #16" << std::endl
		<< "LDP X7, X8, [sp], #16" << std::endl
		<< "MOV W0, WZR" << std::endl
		<< "RET" << std::endl
		<< "LDP X9, X10, [sp], #16" << std::endl
		<< "LDP X7, X8, [sp], #16" << std::endl
		<< "MOV X0, X0" << std::endl
		<< "B #" << avc_denied_entry_hook_jump_back_addr - (hook_func_start_addr + 0x74 + next_asm_line_bytes_cnt) << std::endl;

	std::string strAsmCode = sstrAsm.str();
	std::cout << std::endl << strAsmCode << std::endl;

	std::string strBytes = AsmToBytes(strAsmCode);
	if (!strBytes.length()) {
		return 0;
	}
	size_t nHookFuncSize = strBytes.length() / 2;

	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)&m_file_buf[0] + avc_denied_addr), sizeof(hookOrigCmd));
	std::string strHookOrigCmd = bytes_2_hex_str((const unsigned char*)hookOrigCmd, sizeof(hookOrigCmd));
	strBytes = strBytes.substr(0, (0x70 + next_asm_line_bytes_cnt) * 2) + strHookOrigCmd + strBytes.substr((0x70 + next_asm_line_bytes_cnt + 4) * 2);

	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });
	std::stringstream sstrAsm2;
	sstrAsm2
		<< "B #" << hook_func_start_addr - avc_denied_addr << std::endl;
	std::string strBytes2 = AsmToBytes(sstrAsm2.str());
	if (!strBytes2.length()) {
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ strBytes2, avc_denied_addr });
	hook_func_start_addr += nHookFuncSize;
	std::cout << "#下一段HOOK函数起始可写位置：" << std::hex << hook_func_start_addr << std::endl << std::endl;
	return hook_func_start_addr + nHookFuncSize;
}
