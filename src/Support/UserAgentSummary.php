<?php

declare(strict_types=1);

namespace NutriCompare\Fingerprint\Support;

/**
 * Reduces a User-Agent header to a low-entropy summary such as
 * "Chrome 121 on Windows".
 *
 * WHY NOT HASH IT. A UA string is high-entropy — it IS a browser fingerprint,
 * which is precisely what fingerprinting libraries harvest. Hashing it
 * preserves that identifying power almost exactly while making the stored
 * value *look* anonymised: two requests from the same browser build still
 * collide, so the hash re-identifies a person just as well as the string did.
 * That is the worst of both worlds, so this class discards information instead.
 *
 * WHY A DELIBERATE IMPLEMENTATION RATHER THAN A LIBRARY. CLAUDE.md's
 * Library-First principle requires an objective technical reason to write
 * something a mature package already does, and there is one here. The mature
 * options (matomo/device-detector, whichbrowser/parser, ua-parser/uap-php) are
 * built for ANALYTICS-GRADE DEVICE DETECTION: they optimise for distinguishing
 * as many devices, models and builds as possible, and matomo/device-detector
 * in particular ships thousands of regexes to do it. That objective is the
 * exact inverse of this one. A detector that resolves "Samsung Galaxy S24
 * Ultra, Android 14, Chrome 121.0.6167.85" produces a HIGHER-entropy — more
 * re-identifying — output than the raw header for practical purposes, which
 * would defeat the reason the value is being reduced at all. Fewer buckets is
 * the requirement, not more, so the small deliberate mapping below is the
 * correct tool and a heavyweight parser is the wrong one. It is also one fewer
 * dependency to track for lifecycle and advisories (CLAUDE.md Chapter 7).
 *
 * Consequence, stated rather than hidden: this recognises the mainstream
 * browser and OS families and nothing else. An unrecognised client is reported
 * as unknown rather than guessed at. That is the intended failure mode — an
 * audit trail wants a coarse, honest bucket, and G3 says unknown stays
 * unknown.
 */
final class UserAgentSummary
{
    /**
     * Longest UA string considered. Anything beyond this is ignored rather
     * than scanned: real headers are well under it, and an unbounded string
     * from an untrusted client should never be fed to a regex chain.
     */
    private const MAX_LENGTH = 512;

    private const UNKNOWN = 'Unknown';

    /**
     * Browser families, in priority order — MOST SPECIFIC FIRST, because these
     * tokens deliberately nest. Edge sends "Edg/… Chrome/… Safari/…", Opera
     * sends "OPR/… Chrome/…", and every Chromium browser sends "Safari/…", so
     * matching Chrome or Safari first would mislabel most of the market.
     *
     * Each entry maps a display name to the pattern whose first capture group
     * is the major version.
     *
     * @var array<string, string>
     */
    private const BROWSERS = [
        'Edge' => '/\bEdge?A?i?O?S?\/(\d+)/i',
        'Opera' => '/\bOPR\/(\d+)/i',
        'Samsung Internet' => '/\bSamsungBrowser\/(\d+)/i',
        'Firefox' => '/\bFirefox\/(\d+)/i',
        'Chrome' => '/\b(?:Chrome|CriOS)\/(\d+)/i',
        'Safari' => '/\bVersion\/(\d+).*\bSafari\//i',
    ];

    /**
     * Operating-system families, in priority order — again most specific
     * first. "Android" appears in UA strings that also contain "Linux", and
     * iOS devices report "like Mac OS X", so both would be mislabelled by a
     * naive order.
     *
     * Deliberately family only, never version: "Windows" rather than
     * "Windows 11", because the version adds identifying detail without
     * answering any question this summary exists to answer.
     *
     * @var array<string, string>
     */
    private const OPERATING_SYSTEMS = [
        'Android' => '/\bAndroid\b/i',
        'iOS' => '/\b(?:iPhone|iPad|iPod)\b/i',
        'ChromeOS' => '/\bCrOS\b/i',
        'macOS' => '/\b(?:Macintosh|Mac OS X)\b/i',
        'Windows' => '/\bWindows\b/i',
        'Linux' => '/\b(?:Linux|X11)\b/i',
    ];

    /**
     * Summarise a User-Agent header.
     *
     * Returns null for null and for a blank header — the absence of a header
     * is a real, distinguishable state and is not reported as an unknown
     * browser. A header that is present but unrecognised yields a string
     * naming whichever half was identified, with "Unknown" for the other.
     */
    public static function summarize(?string $userAgent): ?string
    {
        if ($userAgent === null) {
            return null;
        }

        $trimmed = trim($userAgent);

        if ($trimmed === '') {
            return null;
        }

        $subject = substr($trimmed, 0, self::MAX_LENGTH);

        return self::browser($subject).' on '.self::operatingSystem($subject);
    }

    /**
     * Browser family plus major version, e.g. "Chrome 121".
     *
     * The version is included because it is the one piece of an audit record a
     * reader may act on (an admin session from a years-old build is worth a
     * second look) and a major number alone is coarse enough to be shared by
     * millions of clients. Minor and build numbers are dropped: they are what
     * makes a UA string uniquely identifying.
     */
    private static function browser(string $userAgent): string
    {
        foreach (self::BROWSERS as $name => $pattern) {
            // Every pattern in self::BROWSERS has exactly one capture group,
            // so a successful match always populates $matches[1]; guarding it
            // would be dead code.
            if (preg_match($pattern, $userAgent, $matches) === 1) {
                return $name.' '.$matches[1];
            }
        }

        return self::UNKNOWN.' browser';
    }

    private static function operatingSystem(string $userAgent): string
    {
        foreach (self::OPERATING_SYSTEMS as $name => $pattern) {
            if (preg_match($pattern, $userAgent) === 1) {
                return $name;
            }
        }

        return self::UNKNOWN.' OS';
    }
}
