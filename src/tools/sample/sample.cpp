/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Provides a very simple MsQuic API sample server and client application.

    The quicsample app implements a simple protocol (ALPN "sample") where the
    client connects to the server, opens a single bidirectional stream, sends
    some data and shuts down the stream in the send direction. On the server
    side all connections, streams and data are accepted. After the stream is
    shut down, the server then sends its own data and shuts down its send
    direction. The connection only shuts down when the 1 second idle timeout
    triggers.

    A certificate needs to be available for the server to function.

    On Windows, the following PowerShell command can be used to generate a self
    signed certificate with the correct settings. This works for both Schannel
    and OpenSSL TLS providers, assuming the KeyExportPolicy parameter is set to
    Exportable. The Thumbprint received from the command is then passed to this
    sample with -cert_hash:PASTE_THE_THUMBPRINT_HERE

    New-SelfSignedCertificate -DnsName $env:computername,localhost -FriendlyName MsQuic-Test -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable

    On Linux, the following command can be used to generate a self signed
    certificate that works with the OpenSSL TLS Provider. This can also be used
    for Windows OpenSSL, however we recommend the certificate store method above
    for ease of use. Currently key files with password protections are not
    supported. With these files, they can be passed to the sample with
    -cert_file:path/to/server.cert -key_file path/to/server.key

    openssl req  -nodes -new -x509  -keyout server.key -out server.cert

--*/

#include <msquic.h>
#include <stdio.h>
#include <stdlib.h>

#include "quic_platform.h"
#include "quic_trace.h"

#include <sys/socket.h>
#include <sys/errno.h>
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif

//
// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
//
const QUIC_REGISTRATION_CONFIG RegConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

//
// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
//
const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };

//
// The UDP port used by the server side of the protocol.
//
const uint16_t UdpPort = 4567;

//
// The default idle timeout period (1 second) used for the protocol.
//
const uint64_t IdleTimeoutMs = 30000;

//
// The length of buffer sent over the streams in the protocol.
//
//const uint32_t SendBufferLength = 100;

//
// The QUIC API/function table returned from MsQuicOpen. It contains all the
// functions called by the app to interact with MsQuic.
//
const QUIC_API_TABLE* MsQuic;

HQUIC gListener = nullptr;

//
// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
//
HQUIC Registration;

//
// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
//
HQUIC Configuration;

void PrintUsage()
{
    printf(
        "\n"
        "quicsample runs a simple client or server.\n"
        "\n"
        "Usage:\n"
        "\n"
        "  quicsample.exe -client -target:<...> [-unsecure]\n"
        "  quicsample.exe -server -cert_hash:<...> or (-cert_file:<...> and -key_file:<...> (and optionally -password:<...>))\n"
        );
}

//
// Helper function to look up a command line argument.
//
_Ret_maybenull_ _Null_terminated_ const char*
GetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
    )
{
    const size_t nameLen = strlen(name);
    for (int i = 0; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, name, nameLen) == 0) {
            return argv[i] + 1 + nameLen + 1;
        }
    }
    return nullptr;
}

//
// Helper function to convert a hex character to its decimal value.
//
uint8_t DecodeHexChar(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return 0;
}

//
// Helper function to convert a string of hex characters to a byte buffer.
//
uint32_t
DecodeHexBuffer(
    _In_z_ const char* HexBuffer,
    _In_ uint32_t OutBufferLen,
    _Out_writes_to_(OutBufferLen, return)
        uint8_t* OutBuffer
    )
{
    uint32_t HexBufferLen = (uint32_t)strlen(HexBuffer) / 2;
    if (HexBufferLen > OutBufferLen) {
        return 0;
    }

    for (uint32_t i = 0; i < HexBufferLen; i++) {
        OutBuffer[i] =
            (DecodeHexChar(HexBuffer[i * 2]) << 4) |
            DecodeHexChar(HexBuffer[i * 2 + 1]);
    }

    return HexBufferLen;
}

bool IsQuicPacket(const char* data, size_t) {
    const uint8_t* u = reinterpret_cast<const uint8_t*>(data);
    return (u[0] >= 195 && u[0] <= 255) || (u[0] >= 64 && u[0] <= 127); 
}

QUIC_BUFFER *
AllocateBuffer(
    _In_ const char *Buffer,
    _In_ uint32_t Length
    )
{
    if (!Buffer || Length <= 0) {
        printf("Buffer/Length invalid: %u", Length);
        return nullptr;
    }

    //
    // Allocates and builds the buffer to send over the stream.
    //
    auto DataBufferRaw = malloc(sizeof(QUIC_BUFFER) + Length);
    if (DataBufferRaw == nullptr) {
        printf("Buffer allocation failed!\n");
        return nullptr;
    }
    auto DataBuffer = (QUIC_BUFFER*)DataBufferRaw;
    DataBuffer->Buffer = (uint8_t*)DataBufferRaw + sizeof(QUIC_BUFFER);
    DataBuffer->Length = Length;
    memcpy(DataBuffer->Buffer, Buffer, Length);
    return DataBuffer;
}



void
StreamEventRecv(
    _In_ HQUIC Stream,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        {
        uint32_t BufferCount = Event->RECEIVE.BufferCount;
        uint64_t TotalBytes = 0;
        char Buffer[1024] = {0};
        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
            uint32_t DataLength = Event->RECEIVE.Buffers[i].Length;
            TotalBytes += DataLength;

            uint32_t BufferLength = sizeof(Buffer) - 1;
            if (BufferLength >= DataLength) BufferLength = DataLength;
            memset(Buffer, 0, sizeof(Buffer));
            memcpy(Buffer, Event->RECEIVE.Buffers[i].Buffer, BufferLength);
            printf("[strm][%p] Data received str: %s\n", Stream, Buffer);
        }
        printf("[strm][%p] Data received: %u_%" PRIu64 "\n", Stream, BufferCount, TotalBytes);
        break;
        }
    default:
        break;
    }
}

void
DatagramEventRecv(
    _In_ HQUIC Connection,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    char Buffer[1024] = {0};
    uint32_t DataLength = Event->DATAGRAM_RECEIVED.Buffer->Length;
    if (DataLength > 0) {
        uint32_t BufferLength = sizeof(Buffer) - 1;
        if (BufferLength >= DataLength) BufferLength = DataLength;
        memset(Buffer, 0, sizeof(Buffer));
        memcpy(Buffer, Event->DATAGRAM_RECEIVED.Buffer->Buffer, BufferLength);
    }
    printf("[dgrm][%p] Data received str: %s\n", Connection, Buffer);
}

bool
DatagramEventSend(
    _In_ HQUIC Owner,
    _In_ const char *Buffer,
    _In_ uint32_t Length
    )
{
    auto SendBuffer = AllocateBuffer(Buffer, Length);
    if (!SendBuffer) {
        return false;
    }

    printf("[dgrm][%p] Sending data...\n", Owner);

    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = MsQuic->DatagramSend(Owner, SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        auto SendBufferRaw = (void *)SendBuffer;
        free(SendBufferRaw);
        return false;
    }

    return true;
}


bool use_external_server = false;
int udp_socket = INVALID_SOCKET;
struct sockaddr_in peer_addr;

int recv_udp_data(int socket, char *buffer, size_t length) 
{
    struct sockaddr_in cliaddr;
    memset(&cliaddr, 0, sizeof(cliaddr));
    socklen_t addrlen = sizeof(cliaddr);
    int n = recvfrom(socket, buffer, length, 0, (struct sockaddr *)&cliaddr, &addrlen);
    if (n > 0) {
        if (memcmp(&peer_addr, &cliaddr, sizeof(peer_addr)) != 0) {
            printf("[server] set peer addr\n");
            memcpy(&peer_addr, &cliaddr, sizeof(peer_addr));
        }
    }
    return n;
}

bool send_udp_to(int socket, struct sockaddr_in *toaddr, const char *data, size_t length)
{
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int ret = sendto(socket, data, length, 0, (struct sockaddr *)toaddr, addrlen);
    printf("[server], send ret=%d, err=%d_%s\n", ret, errno, strerror(errno));
    if (ret <= 0) {
        return false;
    }
    return true;
}

bool send_udp_data(int socket, int port, const char *data, size_t length)
{
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = INADDR_ANY;
    return send_udp_to(socket, &servaddr, data, length);
}



//
// Allocates and sends some data over a QUIC stream.
//
void
ServerSend(
    _In_ HQUIC Stream,
    _In_ const char *Buffer,
    _In_ uint32_t Length
    )
{
    //
    // Allocates and builds the buffer to send over the stream.
    //
    auto SendBuffer = AllocateBuffer(Buffer, Length);
    if (SendBuffer == nullptr) {
        printf("SendBuffer allocation failed!\n");
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        return;
    }

    printf("[strm][%p] Sending data...\n", Stream);

    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        auto SendBufferRaw = (void *)SendBuffer;
        free(SendBufferRaw);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
}

//
// The server's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ServerStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(Event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        StreamEventRecv(Stream, NULL, Event);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
        ServerSend(Stream, "Test From Server", 16);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", Stream);
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", Connection);
        MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%" PRIu64 "\n", Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        printf("[conn][%p] All done\n", Connection);
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // The peer has started/created a new stream. The app MUST set the
        // callback handler before returning.
        //
        printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, nullptr);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        //
        // The connection succeeded in doing a TLS resumption of a previous
        // connection's session.
        //
        printf("[conn][%p] Connection resumed!\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        printf("[conn][%p] Datagrams unreliable event\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        DatagramEventRecv(Connection, NULL, Event);
        DatagramEventSend(Connection, "Reply datagram to Client", 24);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for listener events from MsQuic.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
ServerListenerCallback(
    _In_ HQUIC /* Listener */,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        //
        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        //
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, nullptr);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
        break;
    default:
        break;
    }
    return Status;
}

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

//
// Helper function to load a server configuration. Uses the command line
// arguments to load the credential part of the configuration.
//
bool
ServerLoadConfiguration(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_SETTINGS Settings{0};
    //
    // Configures the server's idle timeout.
    //
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    //
    // Configures the server's resumption level to allow for resumption and
    // 0-RTT.
    //
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    //
    // Configures the server's settings to allow for the peer to open a single
    // bidirectional stream. By default connections are not configured to allow
    // any streams from the peer.
    //
    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = TRUE;

    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config));
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    // Set unreliable Datagrams
    Settings.DatagramReceiveEnabled = 1;
    Settings.IsSet.DatagramReceiveEnabled = TRUE;

    const char* Cert;
    const char* KeyFile;
    if ((Cert = GetValue(argc, argv, "cert_hash")) != nullptr) {
        //
        // Load the server's certificate from the default certificate store,
        // using the provided certificate hash.
        //
        uint32_t CertHashLen =
            DecodeHexBuffer(
                Cert,
                sizeof(Config.CertHash.ShaHash),
                Config.CertHash.ShaHash);
        if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
            return false;
        }
        Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        Config.CredConfig.CertificateHash = &Config.CertHash;

    } else if ((Cert = GetValue(argc, argv, "cert_file")) != nullptr &&
               (KeyFile = GetValue(argc, argv, "key_file")) != nullptr) {
        //
        // Loads the server's certificate from the file.
        //
        const char* Password = GetValue(argc, argv, "password");
        if (Password != nullptr) {
            Config.CertFileProtected.CertificateFile = (char*)Cert;
            Config.CertFileProtected.PrivateKeyFile = (char*)KeyFile;
            Config.CertFileProtected.PrivateKeyPassword = (char*)Password;
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
            Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
        } else {
            Config.CertFile.CertificateFile = (char*)Cert;
            Config.CertFile.PrivateKeyFile = (char*)KeyFile;
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            Config.CredConfig.CertificateFile = &Config.CertFile;
        }

    } else {
        printf("Must specify ['-cert_hash'] or ['cert_file' and 'key_file' (and optionally 'password')]!\n");
        return false;
    }

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), nullptr, &Configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return false;
    }

    //
    // Loads the TLS credential part of the configuration.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &Config.CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return false;
    }

    return true;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_EXTERNAL_OUTPUT_CALLBACK)
QUIC_STATUS
QUIC_API
ServerOutputCallback(
    _In_ HQUIC /* Listener */,
    _In_opt_ void* /* Context */,
    _In_ void* Buffer,
    _In_ size_t Length
    )
{
    uint8_t *Data = (uint8_t *)Buffer;
    printf("[server] output length=%zu, isquic=%d_%d\n", Length, (int)Data[0], IsQuicPacket((char *)Buffer, Length));
    send_udp_to(udp_socket, &peer_addr, (char *)Buffer, Length);
    return 0;
}

void ServerExternalInput(HQUIC Listener, char* Buffer, size_t Length)
{
    MsQuic->ListenerExternalInput(Listener, Buffer, Length);
}

void start_external_server(int port) {
    printf("[server] start external port:%d\n", port);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        return;
    }

    udp_socket = sock;
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family    = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port);
    if (bind(sock, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        return;
    }

    printf("[server] socket[%d] recving\n", sock);
    char buffer[4096] = {0};
    while(1) {
        int nret = recv_udp_data(sock, buffer, sizeof(buffer));
        if (nret <= 0) break;
        uint8_t *Data = (uint8_t *)buffer;
        printf("[server] recving: %d, isquic=%d_%d\n", nret, (int)Data[0], IsQuicPacket(buffer, nret));
        ServerExternalInput(gListener, buffer, nret);
    }
    printf("[server] quiting ...\n");
}

//
// Runs the server side of the protocol.
//
void
RunServer(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_STATUS Status;
    HQUIC Listener = nullptr;

    use_external_server = true;
    QUIC_EXTERNAL_OUTPUT_CALLBACK_HANDLER Callback = use_external_server?ServerOutputCallback:NULL;

    //
    // Configures the address used for the listener to listen on all IP
    // addresses and the given UDP port.
    //
    QUIC_ADDR Address = {};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&Address, UdpPort);

    //
    // Load the server configuration based on the command line.
    //
    if (!ServerLoadConfiguration(argc, argv)) {
        return;
    }

    //
    // Create/allocate a new listener object.
    //
    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, nullptr, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    gListener = Listener;

    //
    // Starts listening for incoming connections.
    //
    if (QUIC_FAILED(Status = MsQuic->ListenerStartEx(Listener, &Alpn, 1, &Address, Callback))) {
        printf("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    if (use_external_server) {
        start_external_server(UdpPort);
    }

    //
    // Continue listening for connections until the Enter key is pressed.
    //
    printf("Press Enter to exit.\n\n");
    getchar();

Error:

    if (Listener != nullptr) {
        MsQuic->ListenerClose(Listener);
    }
}

//
// The clients's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ClientStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(Event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        StreamEventRecv(Stream, NULL, Event);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", Stream);
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
ClientSend(
    _In_ HQUIC Connection,
    _In_ const char *Buffer,
    _In_ uint32_t Length
    )
{
    QUIC_STATUS Status;
    QUIC_BUFFER *SendBuffer;
    HQUIC Stream = nullptr;

    //
    // Create/allocate a new bidirectional stream. The stream is just allocated
    // and no QUIC stream identifier is assigned until it's started.
    //
    if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, ClientStreamCallback, nullptr, &Stream))) {
        printf("StreamOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("[strm][%p] Starting...\n", Stream);

    //
    // Starts the bidirectional stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    //
    if (QUIC_FAILED(Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
        printf("StreamStart failed, 0x%x!\n", Status);
        MsQuic->StreamClose(Stream);
        goto Error;
    }

    //
    // Allocates and builds the buffer to send over the stream.
    //
    SendBuffer = AllocateBuffer(Buffer, Length);
    if (SendBuffer == nullptr) {
        printf("SendBuffer allocation failed!\n");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    printf("[strm][%p] Sending data...\n", Stream);

    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        auto SendBufferRaw = (void *)SendBuffer;
        free(SendBufferRaw);
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
}

//
// The clients's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", Connection);
        ClientSend(Connection, "Test From Client", 16);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%" PRIu64 "\n", Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        printf("[conn][%p] All done\n", Connection);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->ConnectionClose(Connection);
        }
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        //
        // A resumption ticket (also called New Session Ticket or NST) was
        // received from the server.
        //
        printf("[conn][%p] Resumption ticket received (%u bytes):\n", Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        for (uint32_t i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
            printf("%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
        printf("\n");
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        printf("[conn][%p] Datagrams unreliable event\n", Connection);
        DatagramEventSend(Connection, "Send datagram to Server", 24);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        DatagramEventRecv(Connection, NULL, Event);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// Helper function to load a client configuration.
//
bool
ClientLoadConfiguration(
    bool Unsecure
    )
{
    QUIC_SETTINGS Settings{0};
    //
    // Configures the client's idle timeout.
    //
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    //
    // Default to using the draft-29 version for now, since it's more
    // universally supported by the TLS abstractions currently.
    //
    const uint32_t Version = 0xff00001dU; // IETF draft 29
    Settings.DesiredVersionsList = &Version;
    Settings.DesiredVersionsListLength = 1;
    Settings.IsSet.DesiredVersionsList = TRUE;

    // Set unreliable Datagrams
    Settings.DatagramReceiveEnabled = 1;
    Settings.IsSet.DatagramReceiveEnabled = TRUE;

    //
    // Configures a default client configuration, optionally disabling
    // server certificate validation.
    //
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (Unsecure) {
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), nullptr, &Configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return false;
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return false;
    }

    return true;
}

//
// Runs the client side of the protocol.
//
void
RunClient(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    //
    // Load the client configuration based on the "unsecure" command line option.
    //
    if (!ClientLoadConfiguration(GetValue(argc, argv, "unsecure"))) {
        return;
    }

    QUIC_STATUS Status;
    const char* ResumptionTicketString = nullptr;
    HQUIC Connection = nullptr;

    //
    // Allocate a new connection object.
    //
    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration, ClientConnectionCallback, nullptr, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if ((ResumptionTicketString = GetValue(argc, argv, "ticket")) != nullptr) {
        //
        // If provided at the command line, set the resumption ticket that can
        // be used to resume a previous session.
        //
        uint8_t ResumptionTicket[1024];
        uint16_t TicketLength = (uint16_t)DecodeHexBuffer(ResumptionTicketString, sizeof(ResumptionTicket), ResumptionTicket);
        if (QUIC_FAILED(Status = MsQuic->SetParam(Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_RESUMPTION_TICKET, TicketLength, ResumptionTicket))) {
            printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n", Status);
            goto Error;
        }
    }

    //
    // Get the target / server name or IP from the command line.
    //
    const char* Target;
    if ((Target = GetValue(argc, argv, "target")) == nullptr) {
        printf("Must specify '-target' argument!\n");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    printf("[conn][%p] Connecting...\n", Connection);

    //
    // Start the connection to the server.
    //
    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, Target, UdpPort))) {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status) && Connection != nullptr) {
        MsQuic->ConnectionClose(Connection);
    }
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    //
    // Open a handle to the library and get the API function table.
    //
    if (QUIC_FAILED(Status = MsQuicOpen(&MsQuic))) {
        printf("MsQuicOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Create a registration for the app's connections.
    //
    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (GetValue(argc, argv, "help") || GetValue(argc, argv, "?")) {
        PrintUsage();
    } else if (GetValue(argc, argv, "client")) {
        RunClient(argc, argv);
    } else if (GetValue(argc, argv, "server")) {
        RunServer(argc, argv);
    } else {
        PrintUsage();
    }

Error:

    if (MsQuic != nullptr) {
        if (Configuration != nullptr) {
            MsQuic->ConfigurationClose(Configuration);
        }
        if (Registration != nullptr) {
            //
            // This will block until all outstanding child objects have been
            // closed.
            //
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return (int)Status;
}
