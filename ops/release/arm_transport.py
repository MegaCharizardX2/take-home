"""Wait for a single AKS Run Command without replaying it or logging its response."""
import json
import os
import re
import time

UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
ID = rf'(?:[0-9a-f]{{32}}|{UUID})'
SCOPE = rf'/subscriptions/(?P<sub>{UUID})/resourceGroups/takehome-rg/providers/Microsoft\.ContainerService/managedClusters/aks-outpost/commandResults/'
RESOURCE = re.compile(rf'(?:{SCOPE})?(?P<command>{ID})', re.IGNORECASE)
PENDING = {'Accepted', 'Pending', 'Running', 'InProgress', 'Creating', 'Updating'}
# The CLI's fallback for an HTTP 202 response prints this message even with -o json.
PROGRESS = re.compile(
    rf'command id: (?P<id>{ID}), started at: [^\r\n]{{1,64}}, status: (?P<state>[A-Za-z]+)\r?\n'
    r'Please use command "az aks command result -g takehome-rg -n aks-outpost -i (?P=id)" to get the future execution result',
    re.IGNORECASE,
)


class PollError(ValueError):
    """Fixed diagnostics safe to print in a workflow."""


def _status(raw):
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError, UnicodeError):
        message = PROGRESS.fullmatch(raw.decode('ascii', errors='replace').strip()) if isinstance(raw, bytes) else None
        if message and message['state'] in PENDING:
            return message['id'].lower(), None, message['state']
        raise PollError('Invalid AKS command response') from None
    if not isinstance(doc, dict) or not isinstance(doc.get('id'), str):
        raise PollError('Missing AKS command identity')
    match = RESOURCE.fullmatch(doc['id'])
    if not match:
        raise PollError('Invalid AKS command identity')
    subscription = match['sub'].lower() if match['sub'] else None
    expected = os.environ.get('ARM_SUBSCRIPTION_ID')
    if subscription and expected and subscription != expected.lower():
        raise PollError('Unexpected AKS command scope')
    state = doc.get('provisioningState')
    if not isinstance(state, str):
        raise PollError('Missing AKS provisioning state')
    return match['command'].lower(), subscription, state


def completed_reply(initial_bytes, fetch_result, deadline):
    """Return terminal JSON bytes. deadline is absolute monotonic time, including invoke time."""
    reply = initial_bytes
    expected_id = None
    expected_scope = None
    while True:
        if time.monotonic() >= deadline:
            raise PollError('AKS command deadline exceeded')
        command_id, scope, state = _status(reply)
        if (expected_id and command_id != expected_id) or (scope and expected_scope and scope != expected_scope):
            raise PollError('AKS command identity changed')
        expected_id = command_id
        expected_scope = expected_scope or scope
        if state == 'Succeeded':
            return reply
        if state not in PENDING:
            raise PollError('Unsuccessful AKS command provisioning state')
        time.sleep(min(5, max(0, deadline - time.monotonic())))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PollError('AKS command deadline exceeded')
        try:
            reply = fetch_result(expected_id, remaining)
        except Exception:
            raise PollError('AKS command result lookup failed') from None
