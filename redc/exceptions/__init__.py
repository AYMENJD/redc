r"""RedC exceptions"""

__all__ = [
    "HTTPError",
    "CurlError",
    "UnknownError",
    "UnsupportedProtocolError",
    "FailedInitError",
    "UrlMalformatError",
    "NotBuiltInError",
    "CouldntResolveProxyError",
    "CouldntResolveHostError",
    "CouldntConnectError",
    "WeirdServerReplyError",
    "RemoteAccessDeniedError",
    "FtpAcceptFailedError",
    "FtpWeirdPassReplyError",
    "FtpAcceptTimeoutError",
    "FtpWeirdPasvReplyError",
    "FtpWeird227FormatError",
    "FtpCantGetHostError",
    "Http2Error",
    "FtpCouldntSetTypeError",
    "PartialFileError",
    "FtpCouldntRetrFileError",
    "QuoteErrorError",
    "HttpReturnedErrorError",
    "WriteErrorError",
    "UploadFailedError",
    "ReadErrorError",
    "OutOfMemoryError",
    "OperationTimedoutError",
    "FtpPortFailedError",
    "FtpCouldntUseRestError",
    "RangeErrorError",
    "SslConnectErrorError",
    "BadDownloadResumeError",
    "FileCouldntReadFileError",
    "LdapCannotBindError",
    "LdapSearchFailedError",
    "AbortedByCallbackError",
    "BadFunctionArgumentError",
    "InterfaceFailedError",
    "TooManyRedirectsError",
    "UnknownOptionError",
    "SetoptOptionSyntaxError",
    "GotNothingError",
    "SslEngineNotfoundError",
    "SslEngineSetfailedError",
    "SendErrorError",
    "RecvErrorError",
    "SslCertproblemError",
    "SslCipherError",
    "PeerFailedVerificationError",
    "BadContentEncodingError",
    "FilesizeExceededError",
    "UseSslFailedError",
    "SendFailRewindError",
    "SslEngineInitfailedError",
    "LoginDeniedError",
    "TftpNotfoundError",
    "TftpPermError",
    "RemoteDiskFullError",
    "TftpIllegalError",
    "TftpUnknownidError",
    "RemoteFileExistsError",
    "TftpNosuchuserError",
    "SslCacertBadfileError",
    "RemoteFileNotFoundError",
    "SshError",
    "SslShutdownFailedError",
    "AgainError",
    "SslCrlBadfileError",
    "SslIssuerErrorError",
    "FtpPretFailedError",
    "RtspCseqErrorError",
    "RtspSessionErrorError",
    "FtpBadFileListError",
    "ChunkFailedError",
    "NoConnectionAvailableError",
    "SslPinnedpubkeynotmatchError",
    "SslInvalidcertstatusError",
    "Http2StreamError",
    "RecursiveApiCallError",
    "AuthErrorError",
    "Http3Error",
    "QuicConnectErrorError",
    "ProxyError",
    "SslClientcertError",
    "UnrecoverablePollError",
    "TooLargeError",
    "EchRequiredError",
    "exception_from_code",
]


class HTTPError(Exception):
    r"""HTTP request returned an unsuccessful status code"""

    status_code: int

    def __init__(
        self,
        status_code: int,
        message: str = None,
        response=None,
    ) -> None:
        self.status_code = int(status_code)
        self.response = response

        if message is None:
            message = f"HTTP {self.status_code}"

        super().__init__(message)

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"status_code={self.status_code}, "
            f"message={self.args[0]!r})"
        )


class CurlError(Exception):
    r"""Base class for all libcurl CURLcode errors"""

    code: int
    message: str

    def __init__(self, message: str = None, code: int = None):
        if code is not None:
            self.code = code

        if message is None:
            message = self.message

        super().__init__(message)


class UnknownError(CurlError):
    r"""Unknown libcurl error code"""

    message = "Unknown libcurl error"

    def __init__(self, code: int, message: str = None):
        super().__init__(message=message, code=code)


class UnsupportedProtocolError(CurlError):
    r"""The URL you passed to libcurl used a protocol that this libcurl does not support. The support might be a compile-time option that you did not use, it can be a misspelled protocol string or just a protocol libcurl has no code for"""

    code = 1
    message = "The URL you passed to libcurl used a protocol that this libcurl does not support. The support might be a compile-time option that you did not use, it can be a misspelled protocol string or just a protocol libcurl has no code for"


class FailedInitError(CurlError):
    r"""Early initialization code failed. This is likely to be an internal error or problem, or a resource problem where something fundamental could not get done at init time"""

    code = 2
    message = "Early initialization code failed. This is likely to be an internal error or problem, or a resource problem where something fundamental could not get done at init time"


class UrlMalformatError(CurlError):
    r"""The URL was not properly formatted"""

    code = 3
    message = "The URL was not properly formatted"


class NotBuiltInError(CurlError):
    r"""A requested feature, protocol or option was not found built into this libcurl due to a build-time decision. This means that a feature or option was not enabled or explicitly disabled when libcurl was built and in order to get it to function you have to get a rebuilt libcurl"""

    code = 4
    message = "A requested feature, protocol or option was not found built into this libcurl due to a build-time decision. This means that a feature or option was not enabled or explicitly disabled when libcurl was built and in order to get it to function you have to get a rebuilt libcurl"


class CouldntResolveProxyError(CurlError):
    r"""Could not resolve proxy. The given proxy host could not be resolved"""

    code = 5
    message = "Could not resolve proxy. The given proxy host could not be resolved"


class CouldntResolveHostError(CurlError):
    r"""Could not resolve host. The given remote host was not resolved"""

    code = 6
    message = "Could not resolve host. The given remote host was not resolved"


class CouldntConnectError(CurlError):
    r"""Failed to connect() to host or proxy"""

    code = 7
    message = "Failed to connect() to host or proxy"


class WeirdServerReplyError(CurlError):
    r"""The server sent data libcurl could not parse. This error code was known as CURLE_FTP_WEIRD_SERVER_REPLY before 7.51.0"""

    code = 8
    message = "The server sent data libcurl could not parse. This error code was known as CURLE_FTP_WEIRD_SERVER_REPLY before 7.51.0"


class RemoteAccessDeniedError(CurlError):
    r"""We were denied access to the resource given in the URL. For FTP, this occurs while trying to change to the remote directory"""

    code = 9
    message = "We were denied access to the resource given in the URL. For FTP, this occurs while trying to change to the remote directory"


class FtpAcceptFailedError(CurlError):
    r"""While waiting for the server to connect back when an active FTP session is used, an error code was sent over the control connection or similar"""

    code = 10
    message = "While waiting for the server to connect back when an active FTP session is used, an error code was sent over the control connection or similar"


class FtpWeirdPassReplyError(CurlError):
    r"""After having sent the FTP password to the server, libcurl expects a proper reply. This error code indicates that an unexpected code was returned"""

    code = 11
    message = "After having sent the FTP password to the server, libcurl expects a proper reply. This error code indicates that an unexpected code was returned"


class FtpAcceptTimeoutError(CurlError):
    r"""During an active FTP session while waiting for the server to connect, the [CURLOPT_ACCEPTTIMEOUT_MS](https://curl.se/libcurl/c/CURLOPT_ACCEPTTIMEOUT_MS.html) (or the internal default) timeout expired"""

    code = 12
    message = "During an active FTP session while waiting for the server to connect, the [CURLOPT_ACCEPTTIMEOUT_MS](https://curl.se/libcurl/c/CURLOPT_ACCEPTTIMEOUT_MS.html) (or the internal default) timeout expired"


class FtpWeirdPasvReplyError(CurlError):
    r"""libcurl failed to get a sensible result back from the server as a response to either a PASV or an EPSV command. The server is flawed"""

    code = 13
    message = "libcurl failed to get a sensible result back from the server as a response to either a PASV or an EPSV command. The server is flawed"


class FtpWeird227FormatError(CurlError):
    r"""FTP servers return a 227-line as a response to a PASV command. If libcurl fails to parse that line, this return code is passed back"""

    code = 14
    message = "FTP servers return a 227-line as a response to a PASV command. If libcurl fails to parse that line, this return code is passed back"


class FtpCantGetHostError(CurlError):
    r"""An internal failure to lookup the host used for the new connection"""

    code = 15
    message = "An internal failure to lookup the host used for the new connection"


class Http2Error(CurlError):
    r"""A problem was detected in the HTTP2 framing layer. This is somewhat generic and can be one out of several problems, see the error buffer for details"""

    code = 16
    message = "A problem was detected in the HTTP2 framing layer. This is somewhat generic and can be one out of several problems, see the error buffer for details"


class FtpCouldntSetTypeError(CurlError):
    r"""Received an error when trying to set the transfer mode to binary or ASCII"""

    code = 17
    message = (
        "Received an error when trying to set the transfer mode to binary or ASCII"
    )


class PartialFileError(CurlError):
    r"""A file transfer was shorter or larger than expected. This happens when the server first reports an expected transfer size, and then delivers data that does not match the previously given size"""

    code = 18
    message = "A file transfer was shorter or larger than expected. This happens when the server first reports an expected transfer size, and then delivers data that does not match the previously given size"


class FtpCouldntRetrFileError(CurlError):
    r"""This was either a weird reply to a 'RETR' command or a zero byte transfer complete"""

    code = 19
    message = "This was either a weird reply to a 'RETR' command or a zero byte transfer complete"


class QuoteErrorError(CurlError):
    r"""When sending custom "QUOTE" commands to the remote server, one of the commands returned an error code that was 400 or higher (for FTP) or otherwise indicated unsuccessful completion of the command"""

    code = 21
    message = 'When sending custom "QUOTE" commands to the remote server, one of the commands returned an error code that was 400 or higher (for FTP) or otherwise indicated unsuccessful completion of the command'


class HttpReturnedErrorError(CurlError):
    r"""This is returned if [CURLOPT_FAILONERROR](https://curl.se/libcurl/c/CURLOPT_FAILONERROR.html) is set TRUE and the HTTP server returns an error code that is >= 400"""

    code = 22
    message = "This is returned if [CURLOPT_FAILONERROR](https://curl.se/libcurl/c/CURLOPT_FAILONERROR.html) is set TRUE and the HTTP server returns an error code that is >= 400"


class WriteErrorError(CurlError):
    r"""An error occurred when writing received data to a local file, or an error was returned to libcurl from a write callback"""

    code = 23
    message = "An error occurred when writing received data to a local file, or an error was returned to libcurl from a write callback"


class UploadFailedError(CurlError):
    r"""Failed starting the upload. For FTP, the server typically denied the STOR command. The error buffer usually contains the server's explanation for this"""

    code = 25
    message = "Failed starting the upload. For FTP, the server typically denied the STOR command. The error buffer usually contains the server's explanation for this"


class ReadErrorError(CurlError):
    r"""There was a problem reading a local file or an error returned by the read callback"""

    code = 26
    message = "There was a problem reading a local file or an error returned by the read callback"


class OutOfMemoryError(CurlError):
    r"""A memory allocation request failed. This is serious badness and things are severely screwed up if this ever occurs"""

    code = 27
    message = "A memory allocation request failed. This is serious badness and things are severely screwed up if this ever occurs"


class OperationTimedoutError(CurlError):
    r"""Operation timeout. The specified time-out period was reached according to the conditions"""

    code = 28
    message = "Operation timeout. The specified time-out period was reached according to the conditions"


class FtpPortFailedError(CurlError):
    r"""The FTP PORT command returned error. This mostly happens when you have not specified a good enough address for libcurl to use. See [CURLOPT_FTPPORT](https://curl.se/libcurl/c/CURLOPT_FTPPORT.html)"""

    code = 30
    message = "The FTP PORT command returned error. This mostly happens when you have not specified a good enough address for libcurl to use. See [CURLOPT_FTPPORT](https://curl.se/libcurl/c/CURLOPT_FTPPORT.html)"


class FtpCouldntUseRestError(CurlError):
    r"""The FTP REST command returned error. This should never happen if the server is sane"""

    code = 31
    message = "The FTP REST command returned error. This should never happen if the server is sane"


class RangeErrorError(CurlError):
    r"""The server does not support or accept range requests"""

    code = 33
    message = "The server does not support or accept range requests"


class SslConnectErrorError(CurlError):
    r"""A problem occurred somewhere in the SSL/TLS handshake. You really want the error buffer and read the message there as it pinpoints the problem slightly more. Could be certificates (file formats, paths, permissions), passwords, and others"""

    code = 35
    message = "A problem occurred somewhere in the SSL/TLS handshake. You really want the error buffer and read the message there as it pinpoints the problem slightly more. Could be certificates (file formats, paths, permissions), passwords, and others"


class BadDownloadResumeError(CurlError):
    r"""The download could not be resumed because the specified offset was out of the file boundary"""

    code = 36
    message = "The download could not be resumed because the specified offset was out of the file boundary"


class FileCouldntReadFileError(CurlError):
    r"""A file given with FILE:// could not be opened. Most likely because the file path does not identify an existing file. Did you check file permissions?"""

    code = 37
    message = "A file given with FILE:// could not be opened. Most likely because the file path does not identify an existing file. Did you check file permissions?"


class LdapCannotBindError(CurlError):
    r"""LDAP cannot bind. LDAP bind operation failed"""

    code = 38
    message = "LDAP cannot bind. LDAP bind operation failed"


class LdapSearchFailedError(CurlError):
    r"""LDAP search failed"""

    code = 39
    message = "LDAP search failed"


class AbortedByCallbackError(CurlError):
    r"""Aborted by callback. A callback returned "abort" to libcurl"""

    code = 42
    message = 'Aborted by callback. A callback returned "abort" to libcurl'


class BadFunctionArgumentError(CurlError):
    r"""A function was called with a bad parameter"""

    code = 43
    message = "A function was called with a bad parameter"


class InterfaceFailedError(CurlError):
    r"""Interface error. A specified outgoing interface could not be used. Set which interface to use for outgoing connections' source IP address with [CURLOPT_INTERFACE](https://curl.se/libcurl/c/CURLOPT_INTERFACE.html)"""

    code = 45
    message = "Interface error. A specified outgoing interface could not be used. Set which interface to use for outgoing connections' source IP address with [CURLOPT_INTERFACE](https://curl.se/libcurl/c/CURLOPT_INTERFACE.html)"


class TooManyRedirectsError(CurlError):
    r"""Too many redirects. When following redirects, libcurl hit the maximum amount. Set your limit with [CURLOPT_MAXREDIRS](https://curl.se/libcurl/c/CURLOPT_MAXREDIRS.html)"""

    code = 47
    message = "Too many redirects. When following redirects, libcurl hit the maximum amount. Set your limit with [CURLOPT_MAXREDIRS](https://curl.se/libcurl/c/CURLOPT_MAXREDIRS.html)"


class UnknownOptionError(CurlError):
    r"""An option passed to libcurl is not recognized/known. Refer to the appropriate documentation. This is most likely a problem in the program that uses libcurl. The error buffer might contain more specific information about which exact option it concerns"""

    code = 48
    message = "An option passed to libcurl is not recognized/known. Refer to the appropriate documentation. This is most likely a problem in the program that uses libcurl. The error buffer might contain more specific information about which exact option it concerns"


class SetoptOptionSyntaxError(CurlError):
    r"""An option passed in to a setopt was wrongly formatted. See error message for details about what option"""

    code = 49
    message = "An option passed in to a setopt was wrongly formatted. See error message for details about what option"


class GotNothingError(CurlError):
    r"""Nothing was returned from the server, and under the circumstances, getting nothing is considered an error"""

    code = 52
    message = "Nothing was returned from the server, and under the circumstances, getting nothing is considered an error"


class SslEngineNotfoundError(CurlError):
    r"""The specified crypto engine was not found"""

    code = 53
    message = "The specified crypto engine was not found"


class SslEngineSetfailedError(CurlError):
    r"""Failed setting the selected SSL crypto engine as default"""

    code = 54
    message = "Failed setting the selected SSL crypto engine as default"


class SendErrorError(CurlError):
    r"""Failed sending network data"""

    code = 55
    message = "Failed sending network data"


class RecvErrorError(CurlError):
    r"""Failure with receiving network data"""

    code = 56
    message = "Failure with receiving network data"


class SslCertproblemError(CurlError):
    r"""problem with the local client certificate"""

    code = 58
    message = "problem with the local client certificate"


class SslCipherError(CurlError):
    r"""Could not use specified cipher"""

    code = 59
    message = "Could not use specified cipher"


class PeerFailedVerificationError(CurlError):
    r"""The remote server's SSL certificate or SSH fingerprint was deemed not OK. This error code has been unified with CURLE_SSL_CACERT since 7.62.0. Its previous value was 51"""

    code = 60
    message = "The remote server's SSL certificate or SSH fingerprint was deemed not OK. This error code has been unified with CURLE_SSL_CACERT since 7.62.0. Its previous value was 51"


class BadContentEncodingError(CurlError):
    r"""Unrecognized transfer encoding"""

    code = 61
    message = "Unrecognized transfer encoding"


class FilesizeExceededError(CurlError):
    r"""Maximum file size exceeded"""

    code = 63
    message = "Maximum file size exceeded"


class UseSslFailedError(CurlError):
    r"""Requested FTP SSL level failed"""

    code = 64
    message = "Requested FTP SSL level failed"


class SendFailRewindError(CurlError):
    r"""When doing a send operation curl had to rewind the data to retransmit, but the rewinding operation failed"""

    code = 65
    message = "When doing a send operation curl had to rewind the data to retransmit, but the rewinding operation failed"


class SslEngineInitfailedError(CurlError):
    r"""Initiating the SSL Engine failed"""

    code = 66
    message = "Initiating the SSL Engine failed"


class LoginDeniedError(CurlError):
    r"""The remote server denied curl to login"""

    code = 67
    message = "The remote server denied curl to login"


class TftpNotfoundError(CurlError):
    r"""File not found on TFTP server"""

    code = 68
    message = "File not found on TFTP server"


class TftpPermError(CurlError):
    r"""Permission problem on TFTP server"""

    code = 69
    message = "Permission problem on TFTP server"


class RemoteDiskFullError(CurlError):
    r"""Out of disk space on the server"""

    code = 70
    message = "Out of disk space on the server"


class TftpIllegalError(CurlError):
    r"""Illegal TFTP operation"""

    code = 71
    message = "Illegal TFTP operation"


class TftpUnknownidError(CurlError):
    r"""Unknown TFTP transfer ID"""

    code = 72
    message = "Unknown TFTP transfer ID"


class RemoteFileExistsError(CurlError):
    r"""File already exists and is not overwritten"""

    code = 73
    message = "File already exists and is not overwritten"


class TftpNosuchuserError(CurlError):
    r"""This error should never be returned by a properly functioning TFTP server"""

    code = 74
    message = (
        "This error should never be returned by a properly functioning TFTP server"
    )


class SslCacertBadfileError(CurlError):
    r"""Problem with reading the SSL CA cert (path? access rights?)"""

    code = 77
    message = "Problem with reading the SSL CA cert (path? access rights?)"


class RemoteFileNotFoundError(CurlError):
    r"""The resource referenced in the URL does not exist"""

    code = 78
    message = "The resource referenced in the URL does not exist"


class SshError(CurlError):
    r"""An unspecified error occurred during the SSH session"""

    code = 79
    message = "An unspecified error occurred during the SSH session"


class SslShutdownFailedError(CurlError):
    r"""Failed to shut down the SSL connection"""

    code = 80
    message = "Failed to shut down the SSL connection"


class AgainError(CurlError):
    r"""Socket is not ready for send/recv. Wait until it is ready and try again. This return code is only returned from [curl_easy_recv](https://curl.se/libcurl/c/curl_easy_recv.html) and [curl_easy_send](https://curl.se/libcurl/c/curl_easy_send.html)"""

    code = 81
    message = "Socket is not ready for send/recv. Wait until it is ready and try again. This return code is only returned from [curl_easy_recv](https://curl.se/libcurl/c/curl_easy_recv.html) and [curl_easy_send](https://curl.se/libcurl/c/curl_easy_send.html)"


class SslCrlBadfileError(CurlError):
    r"""Failed to load CRL file"""

    code = 82
    message = "Failed to load CRL file"


class SslIssuerErrorError(CurlError):
    r"""Issuer check failed"""

    code = 83
    message = "Issuer check failed"


class FtpPretFailedError(CurlError):
    r"""The FTP server does not understand the PRET command at all or does not support the given argument. Be careful when using [CURLOPT_CUSTOMREQUEST](https://curl.se/libcurl/c/CURLOPT_CUSTOMREQUEST.html), a custom LIST command is sent with the PRET command before PASV as well"""

    code = 84
    message = "The FTP server does not understand the PRET command at all or does not support the given argument. Be careful when using [CURLOPT_CUSTOMREQUEST](https://curl.se/libcurl/c/CURLOPT_CUSTOMREQUEST.html), a custom LIST command is sent with the PRET command before PASV as well"


class RtspCseqErrorError(CurlError):
    r"""Mismatch of RTSP CSeq numbers"""

    code = 85
    message = "Mismatch of RTSP CSeq numbers"


class RtspSessionErrorError(CurlError):
    r"""Mismatch of RTSP Session Identifiers"""

    code = 86
    message = "Mismatch of RTSP Session Identifiers"


class FtpBadFileListError(CurlError):
    r"""Unable to parse FTP file list (during FTP wildcard downloading)"""

    code = 87
    message = "Unable to parse FTP file list (during FTP wildcard downloading)"


class ChunkFailedError(CurlError):
    r"""Chunk callback reported error"""

    code = 88
    message = "Chunk callback reported error"


class NoConnectionAvailableError(CurlError):
    r"""(For internal use only, is never returned by libcurl) No connection available, the session is queued"""

    code = 89
    message = "(For internal use only, is never returned by libcurl) No connection available, the session is queued"


class SslPinnedpubkeynotmatchError(CurlError):
    r"""Failed to match the pinned key specified with [CURLOPT_PINNEDPUBLICKEY](https://curl.se/libcurl/c/CURLOPT_PINNEDPUBLICKEY.html)"""

    code = 90
    message = "Failed to match the pinned key specified with [CURLOPT_PINNEDPUBLICKEY](https://curl.se/libcurl/c/CURLOPT_PINNEDPUBLICKEY.html)"


class SslInvalidcertstatusError(CurlError):
    r"""Status returned failure when asked with [CURLOPT_SSL_VERIFYSTATUS](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYSTATUS.html)"""

    code = 91
    message = "Status returned failure when asked with [CURLOPT_SSL_VERIFYSTATUS](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYSTATUS.html)"


class Http2StreamError(CurlError):
    r"""Stream error in the HTTP/2 framing layer"""

    code = 92
    message = "Stream error in the HTTP/2 framing layer"


class RecursiveApiCallError(CurlError):
    r"""An API function was called from inside a callback"""

    code = 93
    message = "An API function was called from inside a callback"


class AuthErrorError(CurlError):
    r"""An authentication function returned an error"""

    code = 94
    message = "An authentication function returned an error"


class Http3Error(CurlError):
    r"""A problem was detected in the HTTP/3 layer. This is somewhat generic and can be one out of several problems, see the error buffer for details"""

    code = 95
    message = "A problem was detected in the HTTP/3 layer. This is somewhat generic and can be one out of several problems, see the error buffer for details"


class QuicConnectErrorError(CurlError):
    r"""QUIC connection error. This error may be caused by an SSL library error. QUIC is the protocol used for HTTP/3 transfers"""

    code = 96
    message = "QUIC connection error. This error may be caused by an SSL library error. QUIC is the protocol used for HTTP/3 transfers"


class ProxyError(CurlError):
    r"""Proxy handshake error. [CURLINFO_PROXY_ERROR](https://curl.se/libcurl/c/CURLINFO_PROXY_ERROR.html) provides extra details on the specific problem"""

    code = 97
    message = "Proxy handshake error. [CURLINFO_PROXY_ERROR](https://curl.se/libcurl/c/CURLINFO_PROXY_ERROR.html) provides extra details on the specific problem"


class SslClientcertError(CurlError):
    r"""SSL Client Certificate required"""

    code = 98
    message = "SSL Client Certificate required"


class UnrecoverablePollError(CurlError):
    r"""An internal call to poll() or select() returned error that is not recoverable"""

    code = 99
    message = (
        "An internal call to poll() or select() returned error that is not recoverable"
    )


class TooLargeError(CurlError):
    r"""A value or data field grew larger than allowed"""

    code = 100
    message = "A value or data field grew larger than allowed"


class EchRequiredError(CurlError):
    r"""ECH was attempted but failed"""

    code = 101
    message = "ECH was attempted but failed"


__CODE_TO_EXCEPTION = {
    1: UnsupportedProtocolError,
    2: FailedInitError,
    3: UrlMalformatError,
    4: NotBuiltInError,
    5: CouldntResolveProxyError,
    6: CouldntResolveHostError,
    7: CouldntConnectError,
    8: WeirdServerReplyError,
    9: RemoteAccessDeniedError,
    10: FtpAcceptFailedError,
    11: FtpWeirdPassReplyError,
    12: FtpAcceptTimeoutError,
    13: FtpWeirdPasvReplyError,
    14: FtpWeird227FormatError,
    15: FtpCantGetHostError,
    16: Http2Error,
    17: FtpCouldntSetTypeError,
    18: PartialFileError,
    19: FtpCouldntRetrFileError,
    21: QuoteErrorError,
    22: HttpReturnedErrorError,
    23: WriteErrorError,
    25: UploadFailedError,
    26: ReadErrorError,
    27: OutOfMemoryError,
    28: OperationTimedoutError,
    30: FtpPortFailedError,
    31: FtpCouldntUseRestError,
    33: RangeErrorError,
    35: SslConnectErrorError,
    36: BadDownloadResumeError,
    37: FileCouldntReadFileError,
    38: LdapCannotBindError,
    39: LdapSearchFailedError,
    42: AbortedByCallbackError,
    43: BadFunctionArgumentError,
    45: InterfaceFailedError,
    47: TooManyRedirectsError,
    48: UnknownOptionError,
    49: SetoptOptionSyntaxError,
    52: GotNothingError,
    53: SslEngineNotfoundError,
    54: SslEngineSetfailedError,
    55: SendErrorError,
    56: RecvErrorError,
    58: SslCertproblemError,
    59: SslCipherError,
    60: PeerFailedVerificationError,
    61: BadContentEncodingError,
    63: FilesizeExceededError,
    64: UseSslFailedError,
    65: SendFailRewindError,
    66: SslEngineInitfailedError,
    67: LoginDeniedError,
    68: TftpNotfoundError,
    69: TftpPermError,
    70: RemoteDiskFullError,
    71: TftpIllegalError,
    72: TftpUnknownidError,
    73: RemoteFileExistsError,
    74: TftpNosuchuserError,
    77: SslCacertBadfileError,
    78: RemoteFileNotFoundError,
    79: SshError,
    80: SslShutdownFailedError,
    81: AgainError,
    82: SslCrlBadfileError,
    83: SslIssuerErrorError,
    84: FtpPretFailedError,
    85: RtspCseqErrorError,
    86: RtspSessionErrorError,
    87: FtpBadFileListError,
    88: ChunkFailedError,
    89: NoConnectionAvailableError,
    90: SslPinnedpubkeynotmatchError,
    91: SslInvalidcertstatusError,
    92: Http2StreamError,
    93: RecursiveApiCallError,
    94: AuthErrorError,
    95: Http3Error,
    96: QuicConnectErrorError,
    97: ProxyError,
    98: SslClientcertError,
    99: UnrecoverablePollError,
    100: TooLargeError,
    101: EchRequiredError,
}


def exception_from_code(code: int, message: str = None):
    if code == 0:
        return None

    exc_cls = __CODE_TO_EXCEPTION.get(code)
    if exc_cls is None:
        return UnknownError(code=code, message=message)

    return exc_cls(message=message)
