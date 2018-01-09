"""Test RyuApp that uses the experimental API."""

import os

import zof

from faucet import faucet # pylint: disable=import-error
from faucet import faucet_experimental_api # pylint: disable=import-error


APP = zof.Application('test_faucet_experimental_api')

@APP.bind()
class TestFaucetExperimentalAPI(object):
    """Test experimental API."""

    def _update_test_result(self, result):
        with open(self.result_file_name, 'w') as result_file:
            result_file.write(result)

    def __init__(self, *args, **kwargs):
        super(TestFaucetExperimentalAPI, self).__init__(*args, **kwargs)
        self.result_file_name = os.getenv('API_TEST_RESULT')
        self._update_test_result('not registered')

    @APP.event('FAUCET_API_READY')
    def run_tests(self, event):
        """Retrive config and ensure config for switch name is present."""
        config = event['faucet_api'].get_config()
        self._update_test_result('got config: %s' % config)
        try:
            assert 'faucet-1' in config['dps']
            self._update_test_result('pass')
        except AssertionError as err:
            self._update_test_result(str(err))
