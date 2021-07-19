#include "include.h"
#include "Utils.h"

bool Utils::LoadFile(const std::string& path,std::vector<char> &out)
{
	std::ifstream in;
	in.open(path, std::ios::in | std::ios::binary);

	if (!in.good()) {
		return false;
	}

	in.seekg(0, std::ios::end);
	SIZE_T Size = in.tellg();
	in.seekg(0, std::ios::beg);

	out.resize(Size);

	in.read(out.data(), Size);
	in.close();

	return true;
}

bool Utils::LoadResource(UINT32 index, const std::string& path, std::vector<char>& out)
{
	auto DataHandle = ::FindResourceA(NULL, MAKEINTRESOURCEA(index), path.c_str());

	if (!DataHandle) {
		return false;
	}
	auto DataSize = SizeofResource(NULL, DataHandle);
	auto GlobalHandle = LoadResource(NULL, DataHandle);

	if (!GlobalHandle) {
		return false;
	}

	auto DataBuffer = LockResource(GlobalHandle);

	out.resize(DataSize + 1);
	memcpy(out.data(), DataBuffer, DataSize);
	GlobalUnlock(GlobalHandle);

	return true;
}

HANDLE Utils::OpenProcess(const std::wstring& process_name)
{
	HANDLE Handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (!Handle) {
		return ReCa<HANDLE>(0);
	}

	PROCESSENTRY32W PE32;
	PE32.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(Handle, &PE32)) {
		do {
			if (process_name.compare(PE32.szExeFile) == 0) {
				return ::OpenProcess(
					PROCESS_ALL_ACCESS, 
					false, 
					PE32.th32ProcessID
				);
			}
		} while (Process32NextW(Handle, &PE32));
	}

	return ReCa<HANDLE>(0);
}
