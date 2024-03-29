#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma warning( disable : 4996)
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#include <iostream>
#include <string>
#include <algorithm>

using namespace std;

string FormatAddress(DWORD ip)
{
	struct in_addr paddr;
	paddr.S_un.S_addr = ip;

	return inet_ntoa(paddr);
}

void KillAll(vector<MIB_TCPROW2> const& toKill)
{
	for (auto con : toKill) {

		MIB_TCPROW row;
		row.dwLocalAddr = con.dwLocalAddr;
		row.dwLocalPort = con.dwLocalPort & 0xffff;
		row.dwRemoteAddr = con.dwRemoteAddr;
		row.dwRemotePort = con.dwRemotePort & 0xffff;
		row.dwState = MIB_TCP_STATE_DELETE_TCB;

		cout << "Killing " << FormatAddress(row.dwLocalAddr) << ":" << ntohs(static_cast<u_short>(row.dwLocalPort)) << " -> " << FormatAddress(row.dwRemoteAddr) << ":" << ntohs(static_cast<u_short>(row.dwRemotePort)) << endl;

		DWORD result;
		if ((result = SetTcpEntry(&row)) == 0)
		{
			cout << "Killed." << endl;
		}
		else
		{
			cout << "Windows reported that it failed to kill this connection, but may be lying. The result was " << result << "." << endl;
		}
	}
}

vector<MIB_TCPROW2> GetConnectionsFromProcess(int processIdToKill)
{
	auto tableMemory = vector<uint8_t>(1000000);
	const auto table = reinterpret_cast<MIB_TCPTABLE2*>(&tableMemory[0]);
	ULONG size = static_cast<ULONG>(tableMemory.size());
	if (GetTcpTable2(table, &size, TRUE) != 0)
	{
		throw exception("Failed to get TCP table");
	}

	vector<MIB_TCPROW2> rows;
	copy_if(&table->table[0], &table->table[table->dwNumEntries], back_inserter(rows), [processIdToKill](const MIB_TCPROW2 row) { return row.dwOwningPid == processIdToKill; });

	return rows;
}

int main(const int argc, char const* argv[])
{
	try {
		if (argc != 2)
		{
			throw exception("Process ID is required.");
		}

		auto const processIdToKill = stoi(argv[1]);
		auto const rows = GetConnectionsFromProcess(processIdToKill);
		KillAll(rows);
		cout << "Ensuring all connections were killed..." << endl;
		auto const remainingRows = GetConnectionsFromProcess(processIdToKill);
		if (!remainingRows.empty())
		{
			throw exception("Not all connections were killed.");
		}
		cout << "Done." << endl;
		return 0;
	}
	catch (exception & ex)
	{
		cout << "Failed: " << ex.what() << endl;
		return 1;
	}
}
