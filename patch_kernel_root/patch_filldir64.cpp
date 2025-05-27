#include "patch_filldir64.h"
#include "analyze/ARM_asm.h"
PatchFilldir64::PatchFilldir64(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
	const SymbolAnalyze& symbol_analyze) : PatchBase(file_buf, sym, symbol_analyze) {

}

PatchFilldir64::~PatchFilldir64()
{
}

size_t PatchFilldir64::patch_filldir64(size_t root_key_addr_offset, size_t hook_func_start_addr, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t filldir64_addr = m_sym.filldir64;

	int root_key_adr_offset = root_key_addr_offset - (hook_func_start_addr + 4 * 4);

	size_t filldir64_entry_hook_jump_back_addr = filldir64_addr + 4;
	std::stringstream sstrAsm;
	sstrAsm
		<< "CMP W2, #16" << std::endl
		<< "BNE #72" << std::endl
		<< "STP X7, X8, [sp, #-16]!" << std::endl
		<< "STP X9, X10, [sp, #-16]!" << std::endl
		<< "ADR X7, #" << root_key_adr_offset << std::endl
		<< "MOV X8, #0" << std::endl
		<< "LDRB W9, [X1, X8]" << std::endl
		<< "LDRB W10, [X7, X8]" << std::endl
		<< "CMP W9, W10" << std::endl
		<< "B.NE #32" << std::endl
		<< "ADD X8, X8, 1" << std::endl
		<< "CMP X8, #16" << std::endl
		<< "BLT #-24" << std::endl
		<< "LDP X9, X10, [sp], #16" << std::endl
		<< "LDP X7, X8, [sp], #16" << std::endl
		<< "MOV X0, XZR" << std::endl
		<< "RET" << std::endl
		<< "LDP X9, X10, [sp], #16" << std::endl
		<< "LDP X7, X8, [sp], #16" << std::endl
		<< "MOV X0, X0" << std::endl
		<< "B #" << filldir64_entry_hook_jump_back_addr - (hook_func_start_addr + 0x50) << std::endl;
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
	strBytes = strBytes.substr(0, (0x4C) * 2) + strHookOrigCmd + strBytes.substr((0x4C + 4) * 2);

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
