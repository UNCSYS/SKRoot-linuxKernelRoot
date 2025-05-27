#pragma once
#include <iostream>
#include <vector>
#include "patch_kernel_root.h"
#include "analyze/symbol_analyze.h"
class PatchBase
{
public:
	PatchBase(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
		const SymbolAnalyze& symbol_analyze);
	~PatchBase();
protected:
	int get_cred_atomic_usage_len();
	int get_cred_securebits_padding();
	std::string get_cap_ability_max();
	int get_cap_cnt();
	const std::vector<char>& m_file_buf;
	const KernelSymbolOffset& m_sym;
	const SymbolAnalyze& m_symbol_analyze;
};