#ifndef ARM_ASM_HELPER_H_
#define ARM_ASM_HELPER_H_
#include <string>
#include <windows.h>
#include <fstream>
#include <sstream>
#include <filesystem>
#include "base_func.h"

static std::string AsmToBytes(const std::string& strArm64Asm) {
	//获取汇编文本

	//获取自身运行目录
	char szFileName[MAX_PATH] = { 0 };
	::GetModuleFileNameA(NULL, szFileName, MAX_PATH);
	std::string strMyPath = szFileName;
	strMyPath = strMyPath.substr(0, strMyPath.find_last_of('\\') + 1);

	std::string asmFilePath = strMyPath + "aarch64-linux-android-as.exe";
	if (!std::filesystem::exists(asmFilePath)) {
		std::cerr << "Error: aarch64-linux-android-as.exe not found. Please extract this file from the Android NDK." << std::endl;
		exit(EXIT_FAILURE);
	}

	//写出input.txt
	std::ofstream inputFile;
	inputFile.open(strMyPath + "input.txt", std::ios_base::out | std::ios_base::trunc);
	inputFile << strArm64Asm;
	inputFile.close();

	//ARM64
	DeleteFileA(std::string(strMyPath + "output.txt").c_str());

	std::string cmd = strMyPath + "aarch64-linux-android-as.exe -ahlm " + strMyPath + "input.txt >> " + strMyPath + "output.txt";
	system(cmd.c_str());

	//未开发的
	//ARM：arm-linux-as.exe -ahlm -k -mthumb-interwork -march=armv7-a %s >> %s
	//Thumb：arm-linux-as.exe -ahlm -k -mthumb-interwork -march=armv7 %s >> %s

	//读取output.txt
	std::ifstream in(strMyPath + "output.txt");
	std::stringstream ssOutput;
	std::string line;
	bool bIsFirstLine = true;
	if (in) // 有该文件  
	{
		while (getline(in, line)) // line中不包括每行的换行符  
		{
			if (bIsFirstLine) {
				bIsFirstLine = false;
				continue;
			}
			if (!line.length()) { continue; }
			if (line.length() == 1 && line == "\n") { continue; }
			if (line.find("Error") != -1) {
				in.close();
				return {};
			}
			if (line.find("AARCH64 GAS") != -1) { continue; }

			std::stringstream ssGetMidBuf;
			std::string word;
			ssGetMidBuf << line;
			int n = 0;
			while (ssGetMidBuf >> word) {
				n++;
				if (n == 3) {
					ssOutput << word;
				}
				word.clear();
			}


		}
		in.close();
	}

	return ssOutput.str();

}

static std::string AsmLabelToOffset(const std::string& asm_code, const char* end_label_name, const char* jump_label_name) {
	// 得到结尾位置
	std::string s = asm_code;
	size_t n = s.find(end_label_name);
	if (n == -1) {
		return s;
	}
	std::string before = s.substr(0, n);
	size_t end_back_idx_line = count_endl(before);
	replace_all_distinct(s, end_label_name, "");

	// 逐行切割
	std::vector<std::string> lines;
	{
		std::istringstream iss(s);
		std::string line;
		while (std::getline(iss, line)) {
			if (!line.empty() && line.back() == '\r')
				line.pop_back();
			lines.push_back(line);
		}
	}

	// 替换每一行中的 #JUMP_END
	const std::string placeholder = jump_label_name;
	for (size_t idx = 0; idx < lines.size(); ++idx) {
		auto p = lines[idx].find(placeholder);
		if (p != std::string::npos) {
			int imm = (end_back_idx_line - idx) * 4;
			lines[idx].replace(p, placeholder.size(), std::to_string(imm));
		}
	}

	// 拼回去
	std::string out;
	for (size_t i = 0; i < lines.size(); ++i) {
		out += lines[i];
		out += "\n";
	}
	return out;
}

#endif /* ARM_ASM_HELPER_H_ */
