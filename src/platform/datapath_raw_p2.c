#include "datapath_raw.h"

#include "rte_ring.h"
#include "rte_mbuf.h"
#include "rte_mempool.h"

#pragma warning(disable : 4116)  // unnamed type definition in parentheses
#pragma warning(disable : 4100)  // unreferenced formal parameter

#define P2_QUIC_BURST_SIZE 100

#define P2_QUIC_RX_BURST_SIZE 16  // SAME AS DPDK FROM MSoft
#define P2_QUIC_TX_BURST_SIZE 16  // SAME AS DPDK FROM MSoft
#define P2_RX_RING_NAME "rx-slp-ring-0"
#define P2_TX_RING_NAME "txslp2tx-ring-0"
#define P2_MEMPOOL_NAME "dpdk_sw_global"

typedef struct P2_INTERFACE {
    CXPLAT_INTERFACE;
    struct rte_ring* TxRingBuffer;
    struct rte_mempool* MemoryPool;

} P2_INTERFACE;

typedef struct P2_SLP_RINGS {
    struct rte_ring* RxRing;
    struct rte_ring* TxRing;
} P2_SLP_RINGS;

typedef struct P2_DATAPATH {
    CXPLAT_DATAPATH;
    BOOLEAN Running;
    CXPLAT_THREAD P2Thread;
    QUIC_STATUS StartStatus;
    CXPLAT_POOL AdditionalInfoPool;

    P2_SLP_RINGS Rings;
    P2_INTERFACE Interface;

} P2_DATAPATH;

typedef struct P2_RX_PACKET {
    CXPLAT_RECV_DATA;
    CXPLAT_ROUTE RouteStorage;
    struct rte_mbuf* Mbuf;
    CXPLAT_POOL* OwnerPool;
} P2_RX_PACKET;

typedef struct P2_TX_PACKET {
    CXPLAT_SEND_DATA;
    struct rte_mbuf* Mbuf;
    P2_DATAPATH* P2Dpath;
    P2_INTERFACE* Interface;
} P2_TX_PACKET;

CXPLAT_STATIC_ASSERT(sizeof(P2_TX_PACKET) <= sizeof(P2_RX_PACKET),
                     "Code assumes memory allocated for RX is enough for TX");

CXPLAT_THREAD_CALLBACK(CxPlatP2WorkerThread, Context);
BOOLEAN CxPlatP2Initialize(P2_DATAPATH* P2Dpath);
void CxPlatP2ReadConfig(P2_DATAPATH* P2Dpath);

CXPLAT_RECV_DATA* CxPlatDataPathRecvPacketToRecvData(_In_ const CXPLAT_RECV_PACKET* const Context) {
    return (CXPLAT_RECV_DATA*)(((uint8_t*)Context) - sizeof(P2_RX_PACKET));
}

CXPLAT_RECV_PACKET* CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram) {
    return (CXPLAT_RECV_PACKET*)(((uint8_t*)Datagram) + sizeof(P2_RX_PACKET));
}

_IRQL_requires_max_(PASSIVE_LEVEL) size_t
    CxPlatDpRawGetDatapathSize(_In_opt_ const QUIC_EXECUTION_CONFIG* Config) {
    UNREFERENCED_PARAMETER(Config);
    return sizeof(P2_DATAPATH);
}

_IRQL_requires_max_(PASSIVE_LEVEL) QUIC_STATUS
    CxPlatDpRawInitialize(_Inout_ CXPLAT_DATAPATH* Datapath,
                          _In_ uint32_t ClientRecvContextLength,
                          _In_opt_ const QUIC_EXECUTION_CONFIG* Config) {
    UNREFERENCED_PARAMETER(Config);

    P2_DATAPATH* P2Dpath = (P2_DATAPATH*)Datapath;
    CXPLAT_THREAD_CONFIG ThreadConfig = {0, 0, "P2DPathThread", CxPlatP2WorkerThread, P2Dpath};
    const uint32_t AdditionalBufferSize = sizeof(P2_RX_PACKET) + ClientRecvContextLength;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    // We can potentially read a file and fill all the stuff we need [idea]
    CxPlatP2ReadConfig(P2Dpath);

    CxPlatPoolInitialize(FALSE, AdditionalBufferSize, QUIC_POOL_DATAPATH,
                         &P2Dpath->AdditionalInfoPool);
    CxPlatListInitializeHead(&P2Dpath->Interfaces);
    CxPlatListInsertTail(&P2Dpath->Interfaces, &P2Dpath->Interface.Link);

    // Fill Interface struct data with defaults

    // Tx IPV4 Checksum Offload Enabled by default
    P2Dpath->Interface.OffloadStatus.Transmit.NetworkLayerXsum = TRUE;
    // Tx UDP Checksum Offload Enabled by default
    P2Dpath->Interface.OffloadStatus.Transmit.TransportLayerXsum = TRUE;
    // Rx IPV4 Checksum Offload Enabled by default
    P2Dpath->Interface.OffloadStatus.Receive.NetworkLayerXsum = TRUE;
    // Rx  UDP Checksum Offload enabled by default
    P2Dpath->Interface.OffloadStatus.Receive.TransportLayerXsum = TRUE;

    // Configure all the P2 stuff
    if (CxPlatP2Initialize(P2Dpath) == FALSE) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.", FALSE, "CxPlatP2Initialize");
        goto Error;
    }
    // Create a new thread that it will handle the P2 RX and TX communication between rings
    // If there was no error initializing P2 structs then create the thread
    Status = CxPlatThreadCreate(&ThreadConfig, &P2Dpath->P2Thread);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.", Status, "CxPlatThreadCreate");
        goto Error;
    }
    Status = P2Dpath->StartStatus;

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL) void CxPlatDpRawUninitialize(_In_ CXPLAT_DATAPATH* Datapath) {
    P2_DATAPATH* P2Dpath = (P2_DATAPATH*)Datapath;
    P2Dpath->Running = FALSE;
    CxPlatPoolUninitialize(&P2Dpath->AdditionalInfoPool);
    CxPlatThreadWait(&P2Dpath->P2Thread);
    CxPlatThreadDelete(&P2Dpath->P2Thread);
}

void CxPlatDataPathProcessCqe(_In_ CXPLAT_CQE* Cqe) {
    UNREFERENCED_PARAMETER(Cqe);
}
_IRQL_requires_max_(PASSIVE_LEVEL) void CxPlatP2ReadConfig(P2_DATAPATH* P2Dpath) {
    FILE* File = fopen("p2.ini", "r");
    if (File == NULL) {
        return;
    }
    char Line[256];
    while (fgets(Line, sizeof(Line), File) != NULL) {
        char* Value = strchr(Line, '=');
        if (Value == NULL) {
            continue;
        }
        if (Value[strlen(Value) - 1] == '\n') {
            Value[strlen(Value) - 1] = '\0';
        }

        if (strcmp(Line, "MacAddr") == 0) {
            sscanf(Value, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &P2Dpath->Interface.PhysicalAddress[0],
                   &P2Dpath->Interface.PhysicalAddress[1], &P2Dpath->Interface.PhysicalAddress[2],
                   &P2Dpath->Interface.PhysicalAddress[3], &P2Dpath->Interface.PhysicalAddress[4],
                   &P2Dpath->Interface.PhysicalAddress[5]);
            // strcpy(P2Dpath->Interface.PhysicalAddress, Value);
        }

        if(strcmp(Line,"IfIndex") == 0){
            uint32_t IfIndex;
            sscanf(Value, "%u", &IfIndex);
            P2Dpath->Interface.IfIndex = IfIndex;
            P2Dpath->Interface.ActualIfIndex = IfIndex;
        }
    }
    fclose(File);
}

/**
 * @brief Initialize all P2 related stuff
 *
 * @param P2Dpath
 * @return BOOLEAN TRUE if everything was configured succesfully. False in case of error.
 */
BOOLEAN CxPlatP2Initialize(P2_DATAPATH* P2Dpath) {
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    // Initialize the TxRing
    struct rte_ring* P2TxRing = rte_ring_lookup(P2_TX_RING_NAME);
    if (P2TxRing == NULL) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, P2 TX Ring not found");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }
    P2Dpath->Interface.TxRingBuffer = P2TxRing;

    struct rte_ring* P2RxRing = rte_ring_lookup(P2_RX_RING_NAME);
    if (P2RxRing == NULL) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, P2 RX Ring not found");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }
    P2Dpath->Rings.RxRing = P2RxRing;

    struct rte_mempool* P2MemPool = rte_mempool_lookup("dpdk_sw_global");
    if (P2MemPool == NULL) {
        QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, P2 Ring not found");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }
    P2Dpath->Interface.MemoryPool = P2MemPool;

Error:
    if (QUIC_FAILED(Status)) {
        P2Dpath->StartStatus = Status;

        if (P2Dpath->Interface.TxRingBuffer) {
            P2Dpath->Interface.TxRingBuffer = NULL;
        }
        if (P2Dpath->Rings.RxRing) {
            P2Dpath->Rings.RxRing = NULL;
        }
        if (P2Dpath->Interface.MemoryPool) {
            P2Dpath->Interface.MemoryPool = NULL;
        }
        return FALSE;
    }
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL) void CxPlatDpRawPlumbRulesOnSocket(_In_ CXPLAT_SOCKET* Socket,
                                                                      _In_ BOOLEAN IsCreated) {
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(IsCreated);
    // no-op currently since P2 simply steals all traffic
}

_IRQL_requires_max_(PASSIVE_LEVEL) void CxPlatDpRawAssignQueue(
    _In_ const CXPLAT_INTERFACE* Interface, _Inout_ CXPLAT_ROUTE* Route) {
    Route->Queue = (void*)Interface;  // TODO: CHECK THIS
}

_IRQL_requires_max_(DISPATCH_LEVEL) const CXPLAT_INTERFACE* CxPlatDpRawGetInterfaceFromQueue(
    _In_ const void* Queue) {
    return (const CXPLAT_INTERFACE*)Queue;
}
_IRQL_requires_max_(DISPATCH_LEVEL) void CxPlatDpRawRxFree(
    _In_opt_ const CXPLAT_RECV_DATA* PacketChain) {
    while (PacketChain) {
        const P2_RX_PACKET* Packet = (P2_RX_PACKET*)PacketChain;
        PacketChain = PacketChain->Next;
        rte_pktmbuf_free(Packet->Mbuf);
        CxPlatPoolFree(Packet->OwnerPool, (void*)Packet);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL) CXPLAT_SEND_DATA* CxPlatDpRawTxAlloc(
    _In_ CXPLAT_SOCKET* Socket, _Inout_ CXPLAT_SEND_CONFIG* Config) {
    P2_DATAPATH* P2Dpath = (P2_DATAPATH*)Socket->Datapath;
    P2_TX_PACKET* Packet = CxPlatPoolAlloc(&P2Dpath->AdditionalInfoPool);
    QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(&Config->Route->RemoteAddress);
    P2_INTERFACE* Interface = (P2_INTERFACE*)Config->Route->Queue;

    if (likely(Packet)) {
        Packet->Interface = Interface;
        Packet->Mbuf = rte_pktmbuf_alloc(Interface->MemoryPool);
        if (likely(Packet->Mbuf)) {
            HEADER_BACKFILL HeaderFill = CxPlatDpRawCalculateHeaderBackFill(Family, FALSE);
            Packet->P2Dpath = P2Dpath;
            Packet->Buffer.Length = Config->MaxPacketSize;
            Packet->Mbuf->data_off = 0;
            Packet->Buffer.Buffer = ((uint8_t*)Packet->Mbuf->buf_addr) + HeaderFill.AllLayer;
            Packet->Mbuf->l2_len = HeaderFill.LinkLayer;
            Packet->Mbuf->l3_len = HeaderFill.NetworkLayer;
        } else {
            CxPlatPoolFree(&P2Dpath->AdditionalInfoPool, Packet);
            Packet = NULL;
        }
    }
    return (CXPLAT_SEND_DATA*)Packet;
}

/**
 * @brief Free Pkt and remove it from pool list
 *
 */
_IRQL_requires_max_(DISPATCH_LEVEL) void CxPlatDpRawTxFree(_In_ CXPLAT_SEND_DATA* SendData) {
    P2_TX_PACKET* Packet = (P2_TX_PACKET*)SendData;
    rte_pktmbuf_free(Packet->Mbuf);
    CxPlatPoolFree(&Packet->P2Dpath->AdditionalInfoPool, SendData);
}

/**
 * @brief Enqueue in TX Ring all available packets to sent
 *
 */
_IRQL_requires_max_(DISPATCH_LEVEL) void CxPlatDpRawTxEnqueue(_In_ CXPLAT_SEND_DATA* SendData) {
    P2_TX_PACKET* Packet = (P2_TX_PACKET*)SendData;
    P2_INTERFACE* Interface = Packet->Interface;
    Packet->Mbuf->data_len = (uint16_t)Packet->Buffer.Length;
    Packet->Mbuf->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;

    P2_DATAPATH* P2Dpath = Packet->P2Dpath;
    if (unlikely(rte_ring_mp_enqueue(Interface->TxRingBuffer, Packet->Mbuf) != 0)) {
        rte_pktmbuf_free(Packet->Mbuf);
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "No room in DPDK TX ring buffer");
    }

    CxPlatPoolFree(&P2Dpath->AdditionalInfoPool, Packet);
}

static void CxPlatP2Rx(_In_ P2_DATAPATH* P2Dpath, _In_ P2_INTERFACE* Interface) {
    struct rte_ring* RxRing = P2Dpath->Rings.RxRing;
    void* RxBuffer[P2_QUIC_RX_BURST_SIZE];

    const uint8_t RxBufferCount
        = rte_ring_dequeue_burst(RxRing, (void**)RxBuffer, P2_QUIC_BURST_SIZE, NULL);
    if (unlikely(RxBufferCount == 0)) {
        return;
    }

    P2_RX_PACKET Packet;  // Working space
    CxPlatZeroMemory(&Packet, sizeof(P2_RX_PACKET));
    Packet.Route = &Packet.RouteStorage;
    Packet.Route->Queue = Interface;

    uint16_t PacketCount = 0;
    for (uint8_t i = 0; i < RxBufferCount; i++) {
        struct rte_mbuf* Buffer = (struct rte_mbuf*)RxBuffer[i];
        Packet.Buffer = NULL;
        if ((Buffer->ol_flags & (PKT_RX_IP_CKSUM_BAD | PKT_RX_L4_CKSUM_BAD)) == 0) {
            CxPlatDpRawParseEthernet((CXPLAT_DATAPATH*)P2Dpath, (CXPLAT_RECV_DATA*)&Packet,
                                     ((uint8_t*)Buffer->buf_addr) + Buffer->data_off,
                                     Buffer->pkt_len);
            //
            // The route has been filled in with the packet's src/dst IP and ETH addresses, so
            // mark it resolved. This allows stateless sends to be issued without performing
            // a route lookup.
            //
            Packet.Route->State = RouteResolved;
        } else {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.", Buffer->ol_flags,
                           "L3/L4 checksum incorrect");
        }

        P2_RX_PACKET* NewPacket;
        if (likely(Packet.Buffer
                   && (NewPacket = CxPlatPoolAlloc(&P2Dpath->AdditionalInfoPool)) != NULL)) {
            CxPlatCopyMemory(NewPacket, &Packet, sizeof(P2_RX_PACKET));
            NewPacket->Allocated = TRUE;
            NewPacket->Mbuf = Buffer;
            NewPacket->OwnerPool = &P2Dpath->AdditionalInfoPool;
            NewPacket->Route = &NewPacket->RouteStorage;
            RxBuffer[PacketCount++] = NewPacket;
        } else {
            rte_pktmbuf_free(Buffer);
        }
    }
    if (likely(PacketCount)) {
        CxPlatDpRawRxEthernet((CXPLAT_DATAPATH*)P2Dpath, (CXPLAT_RECV_DATA**)RxBuffer, PacketCount);
    }
}

// TODO: USE 1 RING MAYBE THIS METHOD IS NOT EVEN NEEDED
/*
static void CxPlatP2Tx(_In_ P2_DATAPATH* P2Dpath, _In_ P2_INTERFACE* Interface) {
    // Dequeue from Interface TxRingBuffer (Internal QUIC Ring)
    struct rte_mbuf* Buffers[P2_QUIC_TX_BURST_SIZE];
    const uint16_t BufferCount = (uint16_t)rte_ring_sc_dequeue_burst(
        Interface->TxRingBuffer, (void**)Buffers, P2_QUIC_TX_BURST_SIZE, NULL);
    if (unlikely(BufferCount == 0)) {
        return;
    }

    // Instead of Sending the Packets we just handle to the TxRing
    struct rte_ring* TxRing = P2Dpath->Rings.TxRing;
    const uint16_t TxCount
        = (uint16_t)rte_ring_enqueue_burst(TxRing, (void**)Buffers, BufferCount, NULL);

    if (unlikely(TxCount < BufferCount)) {
        for (uint16_t buf = TxCount; buf < BufferCount; buf++) {
            rte_pktmbuf_free(Buffers[buf]);
        }
    }
}
*/

CXPLAT_THREAD_CALLBACK(CxPlatP2WorkerThread, Context) {
    P2_DATAPATH* P2Dpath = (P2_DATAPATH*)Context;
    CXPLAT_LIST_ENTRY* Entry;
    // I guess the INTERFACE is not needed because it is handled by P2?
    while (likely(P2Dpath->Running)) {
        for (Entry = P2Dpath->Interfaces.Flink; Entry != &P2Dpath->Interfaces;
             Entry = Entry->Flink) {
            P2_INTERFACE* Interface = CXPLAT_CONTAINING_RECORD(Entry, P2_INTERFACE, Link);
            CxPlatP2Rx(P2Dpath, Interface);
            // CxPlatP2Tx(P2Dpath, Interface);
        }
    }

    CXPLAT_THREAD_RETURN(0);
}