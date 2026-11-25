<?php

namespace Clauth\Laravel\Events;

/**
 * A verified webhook from Clauth (access.granted, access.changed, access.removed, user.updated, user.disabled,
 * user.enabled, invite.accepted, ping). Listen with Clauth::onWebhook('access.granted', fn ($e) => …) or as a
 * normal Laravel event. $user is the local user the kit linked or created, when there is one.
 */
class WebhookReceived
{
    public function __construct(
        public readonly string $type,
        public readonly array $data,
        public readonly array $payload,
        public readonly mixed $user = null,
    ) {}

    /** The person's Clauth id (usr_…), when the event is about a person. */
    public function sub(): ?string
    {
        return $this->data['user']['id'] ?? null;
    }
}
