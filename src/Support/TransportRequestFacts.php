<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Support;

use NutriCompare\Fingerprint\Transport\Ja4;
use NutriCompare\Fingerprint\Transport\RawHeaderCapture;
use NutriCompare\Fingerprint\Transport\TransportIntegrity;

/**
 * The parts of a request that TransportIntegrity needs beyond the header pairs.
 *
 * A value object rather than a Symfony Request because the analyser needs the original
 * case and order of header names, which `Request::headers` has already normalised, and
 * because a pure function of its arguments is exhaustively testable.
 *
 * @see TransportIntegrity
 */
final class TransportRequestFacts
{
    public function __construct(
        /**
         * `true` when the terminating server saw the client speak HTTP/2 or HTTP/3. Set
         * from the edge's signed `X-Client-Proto` or the non-`HTTP_` FastCGI param
         * `CLIENT_PROTOCOL` (`fastcgi_param CLIENT_PROTOCOL $server_protocol`), neither of
         * which a client can supply.
         */
        public readonly bool $clientSpokeHttp2 = false,
        public readonly string $method = 'GET',
        public readonly bool $isDocumentRequest = true,
        /** The `:authority` pseudo-header, present on HTTP/2 requests. */
        public readonly ?string $authority = null,
        /** Whether wire-order headers were recoverable; see RawHeaderCapture. */
        public readonly bool $headerOrderAvailable = true,
        /**
         * The JA4 fingerprint the TLS terminator computed, when there was one. Null is
         * the ordinary case until a terminator is configured and is never a finding.
         */
        public readonly ?Ja4 $ja4 = null,
        /** The client-facing protocol string (`HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0`) when known. */
        public readonly ?string $clientProtocol = null,
        /**
         * Whether the headers PHP received are the client's own frame: the protocol came
         * from `CLIENT_PROTOCOL` at the client-facing nginx. False when it came from a
         * separate edge's signed `X-Client-Proto` — the headers are then the edge→pod
         * request, which the proxy rewrites, so frame-level HTTP/2 checks must not run
         * (round-2 WS2-1).
         */
        public readonly bool $headersAreClientFrame = false,
    ) {}
}
