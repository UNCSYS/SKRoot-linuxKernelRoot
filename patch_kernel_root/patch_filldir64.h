#pragma once
#include <iostream>
#include <vector>
#include "patch_kernel_root.h"
#include "analyze/analyze_kernel.h"
class PatchFilldir64
{
public:
	PatchFilldir64(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
		const AnalyzeKernel& analyze_kernel);
	~PatchFilldir64();

	size_t patch_filldir64(size_t root_key_addr_offset, size_t hook_func_start_addr, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);

private:
	const std::vector<char>& m_file_buf;
	const KernelSymbolOffset& m_sym;
	const AnalyzeKernel& m_analyze_kernel;
};