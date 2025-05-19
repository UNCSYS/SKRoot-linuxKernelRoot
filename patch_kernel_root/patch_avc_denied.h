#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"
class PatchAvcDenied : public PatchBase
{
public:
	PatchAvcDenied(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
		const AnalyzeKernel& analyze_kernel);
	~PatchAvcDenied();

	size_t patch_avc_denied(size_t hook_func_start_addr, const std::vector<size_t>& task_struct_offset_cred,
		std::vector<patch_bytes_data>& vec_out_patch_bytes_data);

private:
	int get_need_read_cap_cnt();
};