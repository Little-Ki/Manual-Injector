#pragma once
namespace Utils
{
	bool LoadFile(const std::string& path, std::vector<char>& out);

	bool LoadResource(UINT32 index, const std::string& path, std::vector<char>& out);

	HANDLE OpenProcess(const std::wstring& ProcName);

};

