<?php

declare(strict_types=1);

namespace DeviceId\Tests\Unit\Email;

use DeviceId\Crawlers\ArrayCache;
use DeviceId\Crawlers\RangeFetcher;
use DeviceId\Email\DomainFacts;
use DeviceId\Email\DomainFeed;
use DeviceId\Email\DomainFeedCatalogue;
use DeviceId\Email\DomainLists;
use DeviceId\Email\DomainMailCheck;
use DeviceId\Email\EmailAssessment;
use DeviceId\Email\EmailAssessor;
use DeviceId\Email\EmailNormalizer;
use DeviceId\Email\GeneratedAddress;
use DeviceId\Email\MailDnsResolver;
use DeviceId\Model\FeatureCatalogue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The e-mail module: normalisation, the local domain lists (real lines of the published files),
 * the fail-safe mail-domain check, the local-part heuristics and the assessment that ties them
 * together. A disposable address alone never carries a weight.
 */
final class EmailModuleTest extends TestCase
{
    private int $now = 1_793_000_000;

    /** @var array<string, string|null> */
    private array $bodies = [];

    private int $calls = 0;

    private function fixture(string $name): string
    {
        $text = file_get_contents(__DIR__.'/../../Fixtures/email/'.$name);
        self::assertIsString($text);

        return $text;
    }

    private function fetcher(): RangeFetcher
    {
        return new class($this->bodies, $this->calls) implements RangeFetcher
        {
            /** @param array<string, string|null> $bodies */
            public function __construct(private array &$bodies, private int &$calls) {}

            public function fetch(string $url): ?string
            {
                $this->calls++;

                return $this->bodies[$url] ?? null;
            }
        };
    }

    private function lists(?ArrayCache $cache = null): DomainLists
    {
        $clock = fn (): int => $this->now;

        return new DomainLists(DomainFeedCatalogue::defaults(), $this->fetcher(), $cache ?? new ArrayCache($clock), $clock, 10);
    }

    private function loaded(): DomainLists
    {
        $feeds = DomainFeedCatalogue::defaults();
        $this->bodies = [
            $feeds['disposable_email_domains']->urls[0] => $this->fixture('disposable-email-domains-sample.conf'),
            $feeds['disposable_mx']->urls[0] => $this->fixture('disposable-mx-sample.txt'),
            $feeds['mail_services']->urls[0] => $this->fixture('mailservices-sample.json'),
        ];
        $lists = $this->lists();
        $this->assertSame(['disposable_email_domains' => 'refreshed', 'disposable_mx' => 'refreshed', 'mail_services' => 'refreshed'], $lists->refreshStale());

        return $lists;
    }

    // ------------------------------------------------------------------ normalisation

    /**
     * @return array<string, array{0: string, 1: ?string}>
     */
    public static function addresses(): array
    {
        return [
            'case and spaces' => ['  Naam@Gmail.com ', 'naam@gmail.com'],
            'gmail dots' => ['n.a.a.m@gmail.com', 'naam@gmail.com'],
            'googlemail' => ['n.a.a.m@googlemail.com', 'naam@gmail.com'],
            'plus tag' => ['naam+shop@gmail.com', 'naam@gmail.com'],
            'dots kept elsewhere' => ['first.last@example.nl', 'first.last@example.nl'],
            'plus tag elsewhere' => ['first.last+1@example.nl', 'first.last@example.nl'],
            'leading plus is a real name' => ['+x@example.nl', '+x@example.nl'],
            'trailing dot on the domain' => ['a@example.nl.', 'a@example.nl'],
            'no at' => ['nobody', null],
            'two ats' => ['a@b@example.nl', null],
            'quoted local part' => ['"a b"@example.nl', null],
            'single label domain' => ['a@localhost', null],
            'empty local part' => ['@example.nl', null],
            'angle brackets' => ['<a@example.nl>', null],
            'empty' => ['', null],
        ];
    }

    #[Test]
    #[DataProvider('addresses')]
    public function addresses_reach_one_canonical_form_and_unreadable_ones_are_refused(string $input, ?string $expected): void
    {
        $this->assertSame($expected, EmailNormalizer::canonical($input));
    }

    #[Test]
    public function the_keyed_hash_is_stable_per_mailbox_secret_bound_and_unreadable_input_has_none(): void
    {
        $secret = str_repeat('s', 40);

        $this->assertSame(EmailNormalizer::hash('n.a.a.m+1@googlemail.com', $secret), EmailNormalizer::hash('NAAM@gmail.com', $secret));
        $this->assertNotSame(EmailNormalizer::hash('naam@gmail.com', $secret), EmailNormalizer::hash('naam@gmail.com', str_repeat('t', 40)));
        $this->assertNotSame(EmailNormalizer::hash('naam@gmail.com', $secret), EmailNormalizer::hash('naam@example.nl', $secret));
        $this->assertSame(64, strlen((string) EmailNormalizer::hash('naam@gmail.com', $secret)));
        $this->assertNull(EmailNormalizer::hash('nobody', $secret));
        $this->expectException(\InvalidArgumentException::class);
        EmailNormalizer::hash('naam@gmail.com', 'short');
    }

    #[Test]
    public function alias_spread_counts_addresses_per_mailbox_without_returning_any_address(): void
    {
        $spread = EmailNormalizer::aliasSpread(['test+1@gmail.com', 'test+2@gmail.com', 't.e.s.t@gmail.com', 'test@gmail.com', 'other@example.nl', 'garbage']);

        $this->assertSame(['mailboxes' => 2, 'max_aliases' => 4], $spread);
        $this->assertSame(['mailboxes' => 0, 'max_aliases' => 0], EmailNormalizer::aliasSpread([]));
    }

    // ------------------------------------------------------------------ domain lists

    #[Test]
    public function the_published_list_formats_load_and_classify_domains(): void
    {
        $lists = $this->loaded();

        $mailinator = $lists->lookup('mailinator.com');
        $this->assertSame(DomainFacts::STATE_OK, $mailinator->state);
        $this->assertTrue($mailinator->disposable);
        $this->assertFalse($mailinator->free);

        $this->assertTrue($lists->lookup('gmail.com')->free);
        $this->assertFalse($lists->lookup('gmail.com')->disposable, 'the lists answered and gmail is not on them');
        $this->assertTrue($lists->lookup('hotmail.nl')->free, 'every host of a provider, not only its key');
        $this->assertTrue($lists->lookup('duck.com')->forwarding);
        $this->assertTrue($lists->lookup('relay.firefox.com')->forwarding);
        $this->assertFalse($lists->lookup('ziggo.nl')->free, 'a paid ISP mailbox is not a free provider');
        $other = $lists->lookup('example.nl');
        $this->assertFalse($other->disposable);
        $this->assertFalse($other->free);
        $this->assertFalse($other->forwarding);
    }

    #[Test]
    public function a_subdomain_of_a_disposable_domain_is_disposable_but_a_subdomain_of_a_free_provider_says_nothing(): void
    {
        $lists = $this->loaded();

        $this->assertTrue($lists->lookup('anything.mailinator.com')->disposable);
        $this->assertTrue($lists->lookup('A.B.Mailinator.COM.')->disposable, 'case and a trailing dot do not matter');
        $this->assertFalse($lists->lookup('mailinator.com.example.nl')->disposable, 'a disposable name inside a longer domain is not the domain');
        $this->assertFalse($lists->lookup('student.gmail.com')->free);
        $this->assertFalse($lists->lookup('notmailinator.com')->disposable);
    }

    #[Test]
    public function the_strict_list_is_not_in_the_catalogue_and_no_feed_needs_a_credit(): void
    {
        foreach (DomainFeedCatalogue::defaults() as $feed) {
            $this->assertTrue($feed->isUsableWithout(), $feed->key);
            $this->assertSame('', $feed->attribution);
            $this->assertSame('2026-10-31', $feed->licence['checked_on']);
            $this->assertStringNotContainsString('strict', implode(' ', $feed->urls));
            $this->assertStringStartsWith('https://', $feed->urls[0]);
        }
        $this->assertSame('permitted', DomainFeedCatalogue::defaults()['disposable_email_domains']->licence['status'], 'CC0');

        $credit = new DomainFeed('c', 'C', ['https://c.test/a'], DomainFeed::FORMAT_LINES, [DomainFeed::DISPOSABLE], ['status' => 'permitted', 'note' => '', 'source' => '', 'checked_on' => '2026-10-31'], 'Data by Somebody');
        $this->assertFalse($credit->isUsableWithout());
    }

    #[Test]
    public function without_usable_lists_every_answer_is_unknown_never_clean(): void
    {
        $cold = $this->lists(new ArrayCache);
        $facts = $cold->lookup('mailinator.com');

        $this->assertSame(DomainFacts::STATE_UNAVAILABLE, $facts->state);
        $this->assertNull($facts->disposable);
        $this->assertNull($facts->free);
        $this->assertNull($facts->forwarding);
        $this->assertSame(DomainFacts::STATE_UNAVAILABLE, $cold->lookup('not a domain')->state);

        $calls = $this->calls;
        $cold->lookup('mailinator.com');
        $this->assertSame($calls, $this->calls, 'a lookup never fetches');
    }

    #[Test]
    public function a_list_past_its_maximum_age_is_ignored_and_a_failed_refresh_keeps_the_last_good_one(): void
    {
        $lists = $this->loaded();
        $feeds = DomainFeedCatalogue::defaults();

        $this->now += 40 * 86400;
        $stale = $lists->lookup('mailinator.com');
        $this->assertSame(DomainFacts::STATE_UNAVAILABLE, $stale->state, 'every list is older than its 30 days');
        $this->assertNull($stale->disposable);

        $this->now -= 39 * 86400;
        $this->bodies = [$feeds['disposable_email_domains']->urls[0] => null, $feeds['disposable_email_domains']->urls[1] => "a.example\nb.example\n"];
        $this->assertFalse($lists->refresh('disposable_email_domains'), 'a download that parses to a handful of domains is a truncated file');
        $this->now += 2 * 86400;
        $this->assertTrue($lists->lookup('mailinator.com')->disposable, 'the earlier version still answers');
    }

    #[Test]
    public function a_feed_is_not_fetched_again_before_its_minimum_interval(): void
    {
        $lists = $this->loaded();
        $calls = $this->calls;

        $this->now += 3600;
        $this->assertFalse($lists->refresh('disposable_mx'));
        $this->assertSame($calls, $this->calls);
    }

    // ------------------------------------------------------------------ mail-domain check

    private function resolver(string &$answer): MailDnsResolver
    {
        return new class($answer) implements MailDnsResolver
        {
            public function __construct(private string &$answer) {}

            public function mailStatus(string $domain): string
            {
                if ($this->answer === 'throw') {
                    throw new \RuntimeException('dns down');
                }

                return $this->answer;
            }
        };
    }

    #[Test]
    public function a_domain_without_mail_needs_two_confirmations_an_hour_apart_before_it_is_reported(): void
    {
        $answer = MailDnsResolver::NO_MAIL;
        $check = new DomainMailCheck($this->resolver($answer), new ArrayCache(fn (): int => $this->now), fn (): int => $this->now);

        $this->assertSame(DomainMailCheck::UNKNOWN, $check->peek('nomail.example'), 'never checked is unknown');
        $this->assertSame(DomainMailCheck::UNKNOWN, $check->refresh('nomail.example'), 'one strike');
        $this->now += 600;
        $this->assertSame(DomainMailCheck::UNKNOWN, $check->refresh('nomail.example'), 'a second answer ten minutes later is the same outage');
        $this->now += 3600;
        $this->assertSame(DomainMailCheck::NO_MAIL, $check->refresh('nomail.example'));
        $this->assertSame(DomainMailCheck::NO_MAIL, $check->peek('NoMail.Example.'));
    }

    #[Test]
    public function a_dns_failure_never_changes_a_stored_outcome_and_a_good_answer_clears_the_strikes(): void
    {
        $answer = MailDnsResolver::MAIL_OK;
        $check = new DomainMailCheck($this->resolver($answer), new ArrayCache(fn (): int => $this->now), fn (): int => $this->now);

        $this->assertSame(DomainMailCheck::OK, $check->refresh('good.example'));
        $answer = MailDnsResolver::UNKNOWN;
        $this->assertSame(DomainMailCheck::OK, $check->refresh('good.example'), 'a timeout does not forget a good answer');
        $answer = 'throw';
        $this->assertSame(DomainMailCheck::OK, $check->refresh('good.example'), 'an exception from the resolver is unknown too');

        $answer = MailDnsResolver::NO_MAIL;
        $check->refresh('good.example');
        $this->assertSame(DomainMailCheck::OK, $check->peek('good.example'), 'one bad answer does not flip a domain that was fine');
        $answer = MailDnsResolver::MAIL_OK;
        $this->now += 4000;
        $this->assertSame(DomainMailCheck::OK, $check->refresh('good.example'));
        $answer = MailDnsResolver::NO_MAIL;
        $this->now += 4000;
        $check->refresh('good.example');
        $this->assertSame(DomainMailCheck::OK, $check->peek('good.example'), 'the earlier good answer cleared the strike');
    }

    #[Test]
    public function the_check_has_no_effect_without_a_resolver_or_cache_and_skips_domains_that_need_no_lookup(): void
    {
        $this->assertSame(DomainMailCheck::UNKNOWN, (new DomainMailCheck)->refresh('example.nl'));
        $this->assertSame(DomainMailCheck::UNKNOWN, (new DomainMailCheck)->peek('example.nl'));
        $this->assertFalse(DomainMailCheck::shouldCheck(new DomainFacts(DomainFacts::STATE_OK, false, true, false)), 'a free provider has mail');
        $this->assertFalse(DomainMailCheck::shouldCheck(new DomainFacts(DomainFacts::STATE_OK, true, false, false)), 'already flagged');
        $this->assertTrue(DomainMailCheck::shouldCheck(new DomainFacts(DomainFacts::STATE_OK, false, false, false)));
        $this->assertTrue(DomainMailCheck::shouldCheck(DomainFacts::unknown()), 'with no list, a lookup is the only evidence');
    }

    // ------------------------------------------------------------------ generated local parts

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function localParts(): array
    {
        return [
            'a plain name' => ['jan.jansen', GeneratedAddress::NONE],
            'a dutch surname with consonants' => ['schrijvers', GeneratedAddress::NONE],
            'name and birth year' => ['piet1985', GeneratedAddress::NONE],
            'initial and surname' => ['jwaldershoff', GeneratedAddress::NONE],
            'name with a tag' => ['maria.lopez+shop', GeneratedAddress::NONE],
            'letters then a long number' => ['john82746391', GeneratedAddress::LIKELY],
            'alternating letters and digits' => ['x8k2m9q4w7z1', GeneratedAddress::LIKELY],
            'a hex string' => ['8f3a9c1e7b2d4f60', GeneratedAddress::LIKELY],
            'a keyboard smash' => ['qwrtpsdfgh', GeneratedAddress::POSSIBLE],
            'too short to judge' => ['x7q', GeneratedAddress::NONE],
        ];
    }

    #[Test]
    #[DataProvider('localParts')]
    public function the_generated_heuristic_needs_agreeing_signs_before_it_says_likely(string $local, string $level): void
    {
        $this->assertSame($level, GeneratedAddress::assess($local)['level'], $local);
    }

    #[Test]
    public function a_forwarding_service_is_not_judged_because_its_random_local_parts_are_by_design(): void
    {
        $this->assertSame(GeneratedAddress::NONE, GeneratedAddress::assess('x8k2m9q4w7z1', true)['level']);
    }

    #[Test]
    public function a_family_of_addresses_with_one_stem_is_counted_without_returning_any_address(): void
    {
        $this->assertSame(4, GeneratedAddress::largestStemFamily(['jessica123', 'jessica124', 'jessica130', 'Jessica.131+x', 'bob1', 'bob1', 'kees.de.vries']));
        $this->assertSame(0, GeneratedAddress::largestStemFamily(['kees.de.vries', 'piet']));
        $this->assertSame(1, GeneratedAddress::largestStemFamily(['bob1', 'bob1']), 'the same address twice is one');
    }

    // ------------------------------------------------------------------ assessment

    #[Test]
    public function a_disposable_address_yields_features_and_a_reason_but_no_weight_or_band(): void
    {
        $assessor = new EmailAssessor($this->loaded());

        $assessment = $assessor->assess('x8k2m9q4w7z1+a@mailinator.com');

        $this->assertSame(EmailAssessment::CLASS_DISPOSABLE, $assessment->domainClass);
        $this->assertSame(['email_disposable' => 1.0, 'email_generated' => 1.0, 'email_tagged' => 1.0], $assessment->features());
        $this->assertSame([['code' => 'email_disposable', 'direction' => 'raises'], ['code' => 'email_generated', 'direction' => 'raises']], $assessment->reasons());
        $properties = array_map(static fn (\ReflectionProperty $p): string => $p->getName(), (new \ReflectionClass(EmailAssessment::class))->getProperties());
        foreach (['score', 'band', 'weight', 'verdict'] as $forbidden) {
            $this->assertNotContains($forbidden, $properties, 'an address alone must not be able to block');
        }
        foreach (array_keys($assessment->features()) as $feature) {
            $this->assertTrue(FeatureCatalogue::knows($feature), $feature);
        }
    }

    #[Test]
    public function free_mail_and_a_plus_tag_are_context_not_reasons(): void
    {
        $assessment = (new EmailAssessor($this->loaded()))->assess('Jan.Jansen+shop@Gmail.com');

        $this->assertSame(EmailAssessment::CLASS_FREE, $assessment->domainClass);
        $this->assertSame(['email_free' => 1.0, 'email_tagged' => 1.0], $assessment->features());
        $this->assertSame([], $assessment->reasons());
    }

    #[Test]
    public function a_forwarding_service_is_a_weak_reason_and_an_ordinary_domain_has_none(): void
    {
        $assessor = new EmailAssessor($this->loaded());

        $this->assertSame([['code' => 'email_forwarding_alias', 'direction' => 'raises']], $assessor->assess('x8k2m9q4w7z1@duck.com')->reasons(), 'no email_generated on a forwarding domain');
        $this->assertSame([], $assessor->assess('kees@example.nl')->reasons());
        $this->assertSame(EmailAssessment::CLASS_OTHER, $assessor->assess('kees@example.nl')->domainClass);
    }

    #[Test]
    public function with_no_lists_the_domain_class_is_unknown_and_an_unreadable_address_is_invalid(): void
    {
        $assessor = new EmailAssessor($this->lists(new ArrayCache));

        $this->assertSame(EmailAssessment::CLASS_UNKNOWN, $assessor->assess('kees@mailinator.com')->domainClass);
        $this->assertSame([], $assessor->assess('kees@mailinator.com')->features(), 'unknown is not disposable');
        $this->assertSame(EmailAssessment::CLASS_INVALID, $assessor->assess('not an address')->domainClass);
        $this->assertSame([], $assessor->assess('not an address')->features(), 'a typo is a validation problem, not abuse');
    }

    #[Test]
    public function the_mail_check_result_reaches_the_assessment_only_through_the_cache(): void
    {
        $lists = $this->loaded();
        $answer = MailDnsResolver::NO_MAIL;
        $check = new DomainMailCheck($this->resolver($answer), new ArrayCache(fn (): int => $this->now), fn (): int => $this->now);
        $assessor = new EmailAssessor($lists, $check);

        $this->assertSame(DomainMailCheck::UNKNOWN, $assessor->assess('kees@nomail.example')->mx);
        $assessor->checkDomain('kees@nomail.example');
        $this->now += 4000;
        $this->assertSame(DomainMailCheck::NO_MAIL, $assessor->checkDomain('kees@nomail.example'));

        $assessment = $assessor->assess('kees@nomail.example');
        $this->assertSame(['email_domain_no_mx' => 1.0], $assessment->features());
        $this->assertSame(['domain_class' => 'other', 'mx' => 'no_mail', 'generated' => 'none'], $assessment->trainingBuckets());
        $this->assertSame(DomainMailCheck::UNKNOWN, $assessor->checkDomain('kees@mailinator.com'), 'a disposable domain is not looked up');
        $this->assertSame(DomainMailCheck::UNKNOWN, (new DomainMailCheck(null, new ArrayCache))->peek('mailinator.com'));
    }

    #[Test]
    public function the_training_buckets_hold_no_address_and_no_domain(): void
    {
        $assessment = (new EmailAssessor($this->loaded()))->assess('x8k2m9q4w7z1@mailinator.com');
        $json = json_encode($assessment->trainingBuckets());

        $this->assertSame(['domain_class' => 'disposable', 'mx' => 'unknown', 'generated' => 'likely'], $assessment->trainingBuckets());
        $this->assertStringNotContainsString('mailinator', (string) $json);
        $this->assertStringNotContainsString('@', (string) $json);
    }
}
