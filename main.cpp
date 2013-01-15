#include <stdio.h>
//#include <cstring.h>
#include <windows.h>
#include "helper.h"

BOOL Peeler_DebugInt(HANDLE hProcess, DEBUG_EVENT DebugEv,DWORD *dwContinueStatus);
BOOL Peeler_Debug_Ex_AV(HANDLE hProcess,DEBUG_EVENT DebugEv,DWORD *dwContinueStatus,BOOL Indepth,BOOL ListOut);

PROCESS_INFORMATION pi = {0};
HANDLE Thread=NULL;
HANDLE ThreadEvent=NULL;
void main(int argc, char *args[])
{
  

	if(argc<2)
	{
		printf("Usage - peeler.exe 'FilePath' <-e>\nCreated by Nirmal Singh<nirmalbhary@aol.com> \n");
		return;
	}

	DEBUG_EVENT DebugEv;
	STARTUPINFO sui = {0};
	BOOL SecondProcessCreated=0; //If debugee is going to create new process...
	BOOL SecondEXCEPTION_BREAKPOINT=0; //Only handle default system break point
	wchar_t DLLNAME[MAX_PATH]={0};
	CONTEXT pContext;
	pContext.ContextFlags=CONTEXT_CONTROL;


	sui.cb = sizeof(STARTUPINFO);
	DWORD dwContinueStatus = DBG_CONTINUE;

	BYTE OldByte=0; //For Breakpoint
	
	DWORD dwMonitorDLLLoading=0;//count how many dll were loaded...

	char *strText="SetProcessDEPPolicy";
	HMODULE hKernel32=NULL;
	hKernel32=GetModuleHandle("kernel32.dll");
	
	if(GetProcAddress(hKernel32,"SetProcessDEPPolicy")==NULL)
	{
		printf("This tool does not work on XP - SP2. Use it on XP-SP3");
		return;
	}

	

	if(!CreateProcess(NULL,args[1], NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS |  DEBUG_PROCESS, NULL, NULL, &sui, &pi))
	{
		printf("Error in creating process-");
		displayError(GetLastError());
		return;
	}

	ThreadEvent=CreateEvent( NULL,TRUE,FALSE,TEXT("txtThreadEvent"));

    if (ThreadEvent == NULL) 
    { 
        printf("CreateEvent failed (%d)\n", GetLastError());
        return;
    }

	while(1)
	{
	
	if(!GetThreadContext(pi.hThread,&pContext))
		displayError(GetLastError());
	WaitForDebugEvent(&DebugEv, INFINITE);

	switch (DebugEv.dwDebugEventCode) 
      { 
		

		case CREATE_PROCESS_DEBUG_EVENT:
			if(SecondProcessCreated)
			{
				printf("\nProcess is going to start new process %s\n",DebugEv.u.CreateProcessInfo.lpImageName);
				TerminateProcess(DebugEv.u.CreateProcessInfo.hProcess,0);
				break;

			}
			
			ZeroMemory(&ProcessInfo,sizeof(ProcessInfo));

			ProcessInfo=DebugEv.u.CreateProcessInfo;

			
			
			OldByte=SetBP(pi.hProcess,(DWORD)ProcessInfo.lpStartAddress,"\xCC");
			
			SecondProcessCreated=1;
			
			break;

        case EXCEPTION_DEBUG_EVENT:

			switch(DebugEv.u.Exception.ExceptionRecord.ExceptionCode)
            { 
				case EXCEPTION_BREAKPOINT:
					if((DWORD)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress == (DWORD)ProcessInfo.lpStartAddress)
					//if(!SecondEXCEPTION_BREAKPOINT)
					{
							//Geting thread context of debugee
						// ZeroMemory(&pContext,sizeof(pContext));

						//if(!GetThreadContext(pi.hThread,&pContext))
						//	displayError(GetLastError());
						
						OldByte=SetBP(pi.hProcess,(DWORD)ProcessInfo.lpStartAddress,(char*)&OldByte);
						//pContext.Eip--;
						//SetThreadContext(pi.hThread,&pContext);
						//Sleep(1000);
						LoadDllInDebugee(pi.hThread,pi.hProcess,"peeler.dll");
						Peeler_DebugInt(pi.hProcess,DebugEv,&dwContinueStatus);
						
						//OldByte=SetBP(pi.hProcess,(DWORD)ProcessInfo.lpStartAddress,(char*)&OldByte);

						SecondEXCEPTION_BREAKPOINT++;
					}

					
					//dwContinueStatus=DBG_EXCEPTION_NOT_HANDLED;
					break;
				case EXCEPTION_SINGLE_STEP:
						//pContext.EFlags=pContext.EFlags|0x100;
						//if(!SetThreadContext(pi.hThread,&pContext))
						//	displayError(GetLastError());

					break;

				case EXCEPTION_ACCESS_VIOLATION:
					if((DWORD)DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[0] != 8) //ReadWrite Exception
					{
						dwContinueStatus=DBG_EXCEPTION_NOT_HANDLED;
						break;
					}

					if(!Peeler_Debug_Ex_AV(pi.hProcess,DebugEv,&dwContinueStatus,1,0))//(argc>2)?1:0
					{
						dwContinueStatus=DBG_EXCEPTION_NOT_HANDLED;
						//ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);
						//return;
					}
		


					break;
				default: // Handle other exceptions.
					//dwContinueStatus=DBG_EXCEPTION_NOT_HANDLED;
                  break;
			}
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			
			dwContinueStatus=DBG_TERMINATE_PROCESS;		
			printf(" ---Process exit with ExitCode -%X\n",DebugEv.u.ExitProcess.dwExitCode);
			ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);
			return;
			
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			
			DWORD NByteRead;
			
			if(!ReadProcessMemory(pi.hProcess,DebugEv.u.DebugString.lpDebugStringData,DLLNAME,sizeof(DLLNAME),&NByteRead))
			{
				printf("Unable to read process Memory...\n");
				displayError(GetLastError());
			}
			printf("%s",DLLNAME);
			break;
		
		case LOAD_DLL_DEBUG_EVENT:
			break;

		}//end switch(DebugEv.dwDebugEventCode) 

	ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);
	}//end while(1)

}




BOOL Peeler_DebugInt(HANDLE hProcess, DEBUG_EVENT DebugEv,DWORD *dwContinueStatus)
{
	
	//DWORD ThreadId;
	printf("Entry Point in PE header = %X\n",ProcessInfo.lpStartAddress);
	
	//ThreadId=LoadDllInDebugee(hProcess,"peeler.dll");
	ImageBase=(DWORD)ProcessInfo.lpBaseOfImage;

	GetPESections(hProcess,(void*)ImageBase);

	//ContinueDebugEvent(DebugEv.dwProcessId, ThreadId, *dwContinueStatus);

return 1;
}

BOOL Peeler_Debug_Ex_AV(HANDLE hProcess,DEBUG_EVENT DebugEv,DWORD *dwContinueStatus,BOOL Indepth,BOOL ListOut)
{

	DWORD temp, OldExceptionInformation;

	
	if (DebugEv.u.Exception.dwFirstChance ==0)
	{

		return 1;

	}



	if((DWORD)DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[0] != 8) //ReadWrite Exception
	{
		
				//return 1; //Testing
				return 0;
				temp=ExceptionAddress;
				OldExceptionInformation=ExceptionInformation;
				ExceptionAddress=(DWORD)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress; // if Execute expection is on same address it mean it changing the same memory page
				ExceptionInformation=(DWORD)DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[1];
			
				if( ( temp!=ExceptionAddress ) || ( OldExceptionInformation!=ExceptionInformation ))
				{
					//printf("----------------W Exception-----------------------\n");

					//printf("Write Operation at EIP -%x\n",pContext.Eip);
					//printf("Write Operation on Add -%x\n",DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[1]);
					ZeroMemory(&mbi,sizeof(mbi));													
					if(!VirtualQueryEx(pi.hProcess,(void*)ExceptionInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
					{
							printf("Error in WriteOperation -");
							displayError(GetLastError());
							return 0;
					}
					
					if(!VirtualProtectEx(pi.hProcess,(void *)mbi.BaseAddress,mbi.RegionSize,PAGE_READWRITE,&OldProtect))
					{
								printf("Error in WriteOperation -");
								displayError(GetLastError());
								return 0;
					
					}
					if(!VirtualQueryEx(pi.hProcess,(void*)ExceptionInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
					{
							printf("Error in WriteOperation -");
							displayError(GetLastError());
							return 0;
					}
				
				}

				else
				{


					ZeroMemory(&mbi,sizeof(mbi));													
					if(!VirtualQueryEx(pi.hProcess,(void*)ExceptionInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
					{
							printf("Error in WriteOperation -");
							displayError(GetLastError());
							return 0;
					}
					
					if(!VirtualProtectEx(pi.hProcess,(void *)mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&OldProtect))
					{
								printf("Error in WriteOperation -");
								displayError(GetLastError());
								return 0;
					
					}
					if(!VirtualQueryEx(pi.hProcess,(void*)ExceptionInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
					{
							printf("Error in WriteOperation -");
							displayError(GetLastError());
							return 0;
					}



				}
		*dwContinueStatus=DBG_CONTINUE;
		return 1;
										
	}

	else if((DWORD)DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[0] == 8) // Execution exception...
	{
			if(Thread!=NULL)
			{
				//TerminateThread(Thread,0);
				SetEvent(ThreadEvent);
				//CloseHandle(Thread);
				
			}

			Thread=WatchTime(ProcessInfo.hProcess);

			ExceptionAddress=(DWORD)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress;

			if(!ListOut)
			printf("\r");
			else
			printf("\n");
			printf("Possible unpacked EP -%8x",ExceptionAddress);
			
			if(ExceptionAddress != (DWORD)ProcessInfo.lpStartAddress)
			{

				if(IsUnpacked(ProcessInfo,ExceptionAddress))
				{
					if(Thread)
						{
							TerminateThread(Thread,0);
							
						}
					printf("\nFiles seems unpacked now. Please take the dump and fix imports. After doing so\n");
					printf("Press enter to terminate the debugee.\n");
					getchar();
					ExitNow(ProcessInfo.hProcess);
					
				}
			}

			if((Indepth==1) && (LastExceptionBase !=0) && (LastExceptionMemSize !=0))
				if(!VirtualProtectEx(pi.hProcess,(void *)LastExceptionBase,LastExceptionMemSize,PAGE_READWRITE,&OldProtect))
				{
					printf("Error in WriteOperation -");
					displayError(GetLastError());
					return 0;
				}

			ZeroMemory(&mbi,sizeof(mbi));
			
			DWORD ret=0;
			
			if(((ImageBase & ExceptionAddress)==ImageBase) && (ExceptionAddress >= FirstSectionAddress) )
				ret=GetExpectionLocationBase(&mbi,ExceptionAddress);

			if(!ret) // if exception NOT occurs in image space
			{
				ZeroMemory(&mbi,sizeof(mbi));
				
				if(!VirtualQueryEx(pi.hProcess,(void*)ExceptionAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
				{
						printf("Error in WriteOperation -");
						displayError(GetLastError());
						return 0;
				}
				
				if(mbi.Type==0x00020000)
				{
					if(Thread!=NULL)
					{
						TerminateThread(Thread,0);
				
					}
					if(!VirtualQueryEx(pi.hProcess,mbi.AllocationBase, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
					{
						printf("Error in WriteOperation -");
						displayError(GetLastError());
						return 0;
					}
				}
				if((DWORD)mbi.BaseAddress ==ImageBase)
					mbi.RegionSize=0x1000;
			}

			
			/*if(LastExceptionBase ==(DWORD)mbi.BaseAddress) //Removed because a files was increasing a section size and exception occures in the same section.
			{
				//*dwContinueStatus=DBG_TERMINATE_PROCESS;
				ExitNow(ProcessInfo.hProcess);
				return 0;
			}*/
		 
			LastExceptionBase=(DWORD)mbi.BaseAddress;
			LastExceptionMemSize=mbi.RegionSize;

			if(!VirtualProtectEx(pi.hProcess,(void *)mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&OldProtect))
			{
				printf("Error in WriteOperation -");
				displayError(GetLastError());
				return 0;
			}

	//*dwContinueStatus=DBG_CONTINUE;
	//return 1;
	}
return 1;		
}
