import zof
import os

APP = zof.Application('zof_test_experimental_api')


@APP.event('FAUCET_API_READY')
def _faucet_api_ready(event):
    """Retrieve config and ensure config for switch name is present.
    """
    config = event['faucet_api'].get_config()
    _update_test_result('got config: %s' % config)
    try:
        assert 'faucet-1' in config['dps']
        _update_test_result('pass')
    except AssertionError as err:
        _update_test_result(str(err))


def _update_test_result(result):
    result_file_name = os.getenv('API_TEST_RESULT')
    with open(result_file_name, 'w') as result_file:
        result_file.write(result)
