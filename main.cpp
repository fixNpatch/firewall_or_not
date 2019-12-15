// Need to link with Iphlpapi.lib and Ws2_32.lib
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
// #include "killer.h"


#pragma comment(lib, "iphlpapi.lib")
#pragma warning( disable : 4996)
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

/* Note: could also use malloc() and free() */


std::string FormatAddress(DWORD ip)
{
	struct in_addr paddr;
	paddr.S_un.S_addr = ip;

	return inet_ntoa(paddr);
}

void KillAll(std::vector<MIB_TCPROW2> const& toKill)
{
	for (auto con : toKill) {

		MIB_TCPROW row;
		row.dwLocalAddr = con.dwLocalAddr;
		row.dwLocalPort = con.dwLocalPort & 0xffff;
		row.dwRemoteAddr = con.dwRemoteAddr;
		row.dwRemotePort = con.dwRemotePort & 0xffff;
		row.dwState = MIB_TCP_STATE_DELETE_TCB;

		std::cout << "Killing " << FormatAddress(row.dwLocalAddr) << ":" << ntohs(static_cast<u_short>(row.dwLocalPort)) << " -> " << FormatAddress(row.dwRemoteAddr) << ":" << ntohs(static_cast<u_short>(row.dwRemotePort)) << std::endl;

		DWORD result;
		if ((result = SetTcpEntry(&row)) == 0)
		{
			std::cout << "Killed." << std::endl;
		}
		else
		{
			std::cout << "Windows reported that it failed to kill this connection, but may be lying. The result was " << result << "." << std::endl;
		}
	}
}

std::vector<MIB_TCPROW2> GetConnectionsFromProcess(int processIdToKill)
{
	auto tableMemory = std::vector<uint8_t>(1000000);
	const auto table = reinterpret_cast<MIB_TCPTABLE2*>(&tableMemory[0]);
	ULONG size = static_cast<ULONG>(tableMemory.size());
	if (GetTcpTable2(table, &size, TRUE) != 0)
	{
		throw std::exception("Failed to get TCP table");
	}

	std::vector<MIB_TCPROW2> rows;
	copy_if(&table->table[0], &table->table[table->dwNumEntries], back_inserter(rows), [processIdToKill](const MIB_TCPROW2 row) { return row.dwOwningPid == processIdToKill; });

	return rows;
}

int kill(std::string PID)
{
	try {

		auto const processIdToKill = stoi(PID);
		auto const rows = GetConnectionsFromProcess(processIdToKill);
		KillAll(rows);
		std::cout << "Ensuring all connections were killed..." << std::endl;
		auto const remainingRows = GetConnectionsFromProcess(processIdToKill);
		if (!remainingRows.empty())
		{
			throw std::exception("Not all connections were killed.");
		}
		std::cout << "Done." << std::endl;
		return 0;
	}
	catch (std::exception & ex)
	{
		std::cout << "Failed: " << ex.what() << std::endl;
		return 1;
	}
}

int show()
{
	// Declare and initialize variables
	PMIB_TCPTABLE2 pTcpTable;
	DWORD ulSize = 0;
	DWORD dwRetVal = 0;

	char szLocalAddr[128];
	char szRemoteAddr[128];

	struct in_addr IpAddr;

	int i;

	pTcpTable = (MIB_TCPTABLE2*)MALLOC(sizeof(MIB_TCPTABLE2));
	if (pTcpTable == NULL) {
		printf("Error allocating memory\n");
		return 1;
	}

	ulSize = sizeof(MIB_TCPTABLE);
	// Make an initial call to GetTcpTable2 to
	// get the necessary size into the ulSize variable
	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) ==
		ERROR_INSUFFICIENT_BUFFER) {
		FREE(pTcpTable);
		pTcpTable = (MIB_TCPTABLE2*)MALLOC(ulSize);
		if (pTcpTable == NULL) {
			printf("Error allocating memory\n");
			return 1;
		}
	}


	// Make a second call to GetTcpTable to get
	// the actual data we require
	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) {
		printf("\tNumber of entries: %d\n", (int)pTcpTable->dwNumEntries);
		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
			strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
			strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));
			DWORD PID = (u_long)pTcpTable->table[i].dwOwningPid;


			printf("\n\tTCP[%d] State: %ld - ", i,
				pTcpTable->table[i].dwState);
			switch (pTcpTable->table[i].dwState) {
			case MIB_TCP_STATE_CLOSED:
				printf("CLOSED\n");
				break;
			case MIB_TCP_STATE_LISTEN:
				printf("LISTEN\n");
				break;
			case MIB_TCP_STATE_SYN_SENT:
				printf("SYN-SENT\n");
				break;
			case MIB_TCP_STATE_SYN_RCVD:
				printf("SYN-RECEIVED\n");
				break;
			case MIB_TCP_STATE_ESTAB:
				printf("ESTABLISHED\n");
				break;
			case MIB_TCP_STATE_FIN_WAIT1:
				printf("FIN-WAIT-1\n");
				break;
			case MIB_TCP_STATE_FIN_WAIT2:
				printf("FIN-WAIT-2 \n");
				break;
			case MIB_TCP_STATE_CLOSE_WAIT:
				printf("CLOSE-WAIT\n");
				break;
			case MIB_TCP_STATE_CLOSING:
				printf("CLOSING\n");
				break;
			case MIB_TCP_STATE_LAST_ACK:
				printf("LAST-ACK\n");
				break;
			case MIB_TCP_STATE_TIME_WAIT:
				printf("TIME-WAIT\n");
				break;
			case MIB_TCP_STATE_DELETE_TCB:
				printf("DELETE-TCB\n");
				break;
			default:
				printf("UNKNOWN dwState value\n");
				break;
			}
			printf("\tTCP[%d] Local Addr: %s\n", i, szLocalAddr);
			printf("\tTCP[%d] Local Port: %d \n", i,
				ntohs((u_short)pTcpTable->table[i].dwLocalPort));
			printf("\tTCP[%d] Remote Addr: %s\n", i, szRemoteAddr);
			printf("\tTCP[%d] Remote Port: %d\n", i,
				ntohs((u_short)pTcpTable->table[i].dwRemotePort));
			printf("\tTCP[%d] ProcessId: %d\n", i, PID);
		}
	}
	else {
		printf("\tGetTcpTable failed with %d\n", dwRetVal);
		FREE(pTcpTable);
		return 1;
	}

	if (pTcpTable != NULL) {
		FREE(pTcpTable);
		pTcpTable = NULL;
	}

	return 0;
}


int main()
{

	while(true)
	{
		std::string keyChain;
		std::cout << ">>> ----------------------------------------------\nEnter ProcessID or type one of command:\n\n1. 'Exit' to stop program\n2. 'Show' to show TCP Table\n\n>>>";
		std::cin >> keyChain;

		if(keyChain == "Exit")
		{
			break;
		} else if (keyChain == "Show")
		{
			show();
		}
		auto result = kill(keyChain);
	}

	return 0;
}

