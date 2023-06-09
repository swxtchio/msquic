/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC raw datapath socket and IP framing abstractions

--*/

#include "datapath_raw_linux.h"
#ifdef QUIC_CLOG
#include "datapath_raw_socket_linux.c.clog.h"
#endif

#pragma warning(disable : 4116)  // unnamed type definition in parentheses
#pragma warning(disable : 4100)  // unreferenced formal parameter

//
// Socket Pool Logic
//

BOOLEAN
CxPlatSockPoolInitialize(_Inout_ CXPLAT_SOCKET_POOL* Pool) {
    if (!CxPlatHashtableInitializeEx(&Pool->Sockets, CXPLAT_HASH_MIN_SIZE)) {
        return FALSE;
    }
    CxPlatRwLockInitialize(&Pool->Lock);
    return TRUE;
}

void CxPlatSockPoolUninitialize(_Inout_ CXPLAT_SOCKET_POOL* Pool) {
    CxPlatRwLockUninitialize(&Pool->Lock);
    CxPlatHashtableUninitialize(&Pool->Sockets);
}

void CxPlatRemoveSocket(_In_ CXPLAT_SOCKET_POOL* Pool, _In_ CXPLAT_SOCKET* Socket) {
    CxPlatRwLockAcquireExclusive(&Pool->Lock);
    CxPlatHashtableRemove(&Pool->Sockets, &Socket->Entry, NULL);
    CxPlatRwLockReleaseExclusive(&Pool->Lock);
}

_IRQL_requires_max_(PASSIVE_LEVEL) QUIC_STATUS
    CxPlatResolveRoute(_In_ CXPLAT_SOCKET* Socket,
                       _Inout_ CXPLAT_ROUTE* Route,
                       _In_ uint8_t PathId,
                       _In_ void* Context,
                       _In_ CXPLAT_ROUTE_RESOLUTION_CALLBACK_HANDLER Callback) {
    QUIC_ADDR LocalAddress = {0};
    CXPLAT_ROUTE_STATE State = Route->State;
    CXPLAT_DBG_ASSERT(!QuicAddrIsWildCard(&Route->RemoteAddress));
    Route->State = RouteResolving;

    LocalAddress = Route->LocalAddress;
    CXPLAT_LIST_ENTRY* Entry = Socket->Datapath->Interfaces.Flink;
    CXPLAT_INTERFACE* Interface = CONTAINING_RECORD(Entry, CXPLAT_INTERFACE, Link);
    CXPLAT_DBG_ASSERT(sizeof(Interface->PhysicalAddress) == sizeof(Route->LocalLinkLayerAddress));
    CxPlatCopyMemory(&Route->LocalLinkLayerAddress, Interface->PhysicalAddress,
                     sizeof(Route->LocalLinkLayerAddress));
    CxPlatDpRawAssignQueue(Interface, Route);

    if (Route->Queue == NULL) {
        QuicTraceEvent(DatapathError, "[data][%p] ERROR, %s.", Socket,
                       "no matching interface/queue");
        goto Done;
    }



    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Route);
    UNREFERENCED_PARAMETER(PathId);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Callback);
    return QUIC_STATUS_NOT_SUPPORTED;
}

QUIC_STATUS
CxPlatTryAddSocket(_In_ CXPLAT_SOCKET_POOL* Pool, _In_ CXPLAT_SOCKET* Socket) {
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry;

    // We dont need sockets for a P2 Implementation
    Socket->AuxSocket = INVALID_SOCKET;

    CxPlatRwLockAcquireExclusive(&Pool->Lock);
    Entry = CxPlatHashtableLookup(&Pool->Sockets, Socket->LocalAddress.Ipv4.sin_port, &Context);
    while (Entry != NULL) {
        CXPLAT_SOCKET* Temp = CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_SOCKET, Entry);
        if (CxPlatSocketCompare(Temp, &Socket->LocalAddress, &Socket->RemoteAddress)) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            break;
        }
        Entry = CxPlatHashtableLookupNext(&Pool->Sockets, &Context);
    }
    if (QUIC_SUCCEEDED(Status)) {
        CxPlatHashtableInsert(&Pool->Sockets, &Socket->Entry, Socket->LocalAddress.Ipv4.sin_port,
                              &Context);
    }
    CxPlatRwLockReleaseExclusive(&Pool->Lock);

    return Status;
}