// Manual Injector.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "include.h"


int main(int argc, char** argv)
{
	std::vector<char> Data;
	HANDLE ProcessHandle;
	InjectData InjData;
	if (!(ProcessHandle = Utils::OpenProcess(L"notepad.exe"))) {
		std::cout << "Cannot open target process.\n";
		return 0;
	}

	if (!Utils::LoadFile("DLL.dll", Data)) {
		std::cout << "Cannot open file.\n";
		return 0;
	}

	if (!ManualInject(Data.data(), ProcessHandle)) {
		std::cout << "Inject module filed.\n";
		return 0;
	}


	return 0;
}
