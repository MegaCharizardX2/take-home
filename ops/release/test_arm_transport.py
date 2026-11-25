import json
from unittest import TestCase, mock

from arm_transport import completed_reply, PollError

COMMAND = 'a' * 32
SUB = 'aaaaaaaa-0101-0202-0303-aaaaaaaaaaaa'
SCOPE = f'/subscriptions/{SUB}/resourceGroups/takehome-rg/providers/Microsoft.ContainerService/managedClusters/aks-outpost/commandResults/'


def response(state, command=COMMAND):
    return json.dumps({'id': command, 'provisioningState': state, 'logs': 'private', 'exitCode': 0}).encode()


class CommandPoll(TestCase):
    def setUp(self):
        self.now = 300
        for patch in (mock.patch('arm_transport.time.monotonic', lambda: self.now),
                      mock.patch('arm_transport.time.sleep', self.advance),
                      mock.patch.dict('os.environ', ARM_SUBSCRIPTION_ID=SUB)):
            patch.start()
            self.addCleanup(patch.stop)

    def advance(self, seconds):
        self.now += seconds

    def test_validate_terminal_without_polling(self):
        fetch = mock.Mock()
        final = response('Succeeded', SCOPE + COMMAND)
        self.assertEqual(completed_reply(final, fetch, 310), final)
        fetch.assert_not_called()

    def test_pending_cli_and_arm_results_poll_same_leaf_id(self):
        final = response('Succeeded')
        pending = (f'command id: {COMMAND}, started at: None, status: Running\n'
                   f'Please use command "az aks command result -g takehome-rg -n aks-outpost -i {COMMAND}" to get the future execution result\n').encode()
        fetch = mock.Mock(side_effect=[pending, final])
        self.assertEqual(completed_reply(response('Accepted', SCOPE + COMMAND), fetch, 325), final)
        self.assertEqual(fetch.call_args_list, [mock.call(COMMAND, 20), mock.call(COMMAND, 15)])

    def test_unknown_state_scope_id_or_transport_error_is_sanitized(self):
        for bad in (response('Failed'), response('Surprise'), response('Succeeded', 'b' * 32),
                    response('Running', SCOPE.replace(SUB, 'b' * 8 + SUB[8:]) + COMMAND),
                    response('Succeeded', '../secret'), b'private server response', b'null', b'{}'):
            with self.subTest(input=bad), self.assertRaises(PollError) as caught:
                completed_reply(response('Running'), mock.Mock(return_value=bad), self.now + 15)
            self.assertNotIn('private', str(caught.exception))
        with self.assertRaisesRegex(PollError, '^AKS command result lookup failed$'):
            completed_reply(response('Running'), mock.Mock(side_effect=ValueError('private exception')), self.now + 15)

    def test_deadline_includes_polling_and_fetch_time(self):
        fetch = mock.Mock(return_value=response('Running'))
        with self.assertRaisesRegex(PollError, 'deadline'):
            completed_reply(response('InProgress'), fetch, 307)
        fetch.assert_called_once_with(COMMAND, 2)

        def slow_success(command_id, remaining):
            self.advance(remaining + 1)
            return response('Succeeded', command_id)

        with self.assertRaisesRegex(PollError, 'deadline'):
            completed_reply(response('Running'), slow_success, self.now + 10)
