#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"
class PatchFilldir64 : public PatchBase
{
public:
	PatchFilldir64(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
		const SymbolAnalyze& symbol_analyze);
	~PatchFilldir64();

	size_t patch_filldir64(size_t root_key_addr_offset, size_t hook_func_start_addr, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);
};