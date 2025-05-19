#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"
class PatchFreezeTask : public PatchBase
{
public:
	PatchFreezeTask(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
		const AnalyzeKernel& analyze_kernel);
	~PatchFreezeTask();

	size_t patch_freeze_task(size_t hook_func_start_addr, const std::vector<size_t>& task_struct_offset_cred,
		std::vector<patch_bytes_data>& vec_out_patch_bytes_data);

private:
	int get_need_read_cap_cnt();
};