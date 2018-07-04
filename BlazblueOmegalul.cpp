#include "stdafx.h"
#include <iostream>
#include <Windows.h>
#include <atlstr.h>  
#include <Psapi.h>
#include "Stuff.h"
#include <string>

int main()
{
	//55 8B EC 8B 45 0C 83 F8 08
	char process[] = "BBTag.exe";
	char pattern[] = "\x84\x84\x32\x40\x82\x27\x00\xB8\x00\x00\x00\x00\x5E\x0F\x95\xC0";
	char mask[] = "xxxxxxxxxxxxxxxx";
	char colorPattern[] = "\x55\x8B\xEC\x8B\x45\x0C\x83\xF8\x08";
	char colorMask[] = "xxxxxxxxx";
	BYTE inject[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5E, 0x90, 0x90, 0x90 };
	BYTE injectColors[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00, 0x90 };

	DWORD injectSize = sizeof(inject);
	DWORD injectSizeColors = sizeof(injectColors);
	BYTE offset = 0x7;

	DWORD pID = GetPID(process);
	if (!pID) {
		std::cout << "Process not found. (" + std::string(process) << ")" << std::endl;
		std::cin.get();
		return 1;
	}

	HANDLE pHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, pID);
	if (!pHandle) {
		std::cout << "Failed to get process handle. Try running as admin." << std::endl;
		std::cin.get();
		return 1;
	}

	std::cout << "Scanning process...(" << std::string(pattern) << ")" << std::endl;

	DWORD addressXD = ExternalAoBScan(pHandle, pID, process, pattern, mask);

	if (addressXD)
	{
		std::cout << "Memory Pointer found. Unlocking Characters..." << std::endl;
		addressXD += offset;
		WriteProcessMemory(pHandle, (LPVOID)addressXD, &inject, injectSize, NULL);
		std::cout << "Character DLCs Unlocked!" << std::endl;
	}
	else
	{
		std::cout << "Something failed. Please try again." << std::endl;
	}

	DWORD colors = ExternalAoBScan(pHandle, pID, process, colorPattern, colorMask);

	if (colors)
	{
		std::cout << "Memory Pointer found. Unlocking Colors..." << std::endl;
		WriteProcessMemory(pHandle, (LPVOID)colors, &injectColors, injectSizeColors, NULL);
		CloseHandle(pHandle);
		std::cout << "Color DLCs Unlocked!" << std::endl;
	}
	else
	{
		std::cout << "Something failed. Please try again." << std::endl;
	}

	std::cin.get();
	return 0;
}
