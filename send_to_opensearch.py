from logging import getLogger
from opensearchpy import OpenSearch, ConnectionError
from time import perf_counter
from config import PASSWORD, USERNAME, SSL_CERTIFICATE

logger = getLogger(__name__)


def sent_data_to_opensearch(func):
    """Function-decorator. Returns execution time and sends filtered data to Opensearch server"""

    try:
        connection = OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            http_auth=(USERNAME, PASSWORD),
            use_ssl=True,
            verify_certs=True,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
            ca_certs=SSL_CERTIFICATE
        )
    except ConnectionError as error:
        logger.error("[-] Failed to connect to OpenSearch: %s", error)
        return f"Failed to connect to OpenSearch: {error}"

    def inner(*args, **kwargs):
        start = perf_counter()

        try:
            data = func(*args, **kwargs)
            response = connection.index(index='python_index', body=data)
        except Exception as ex:
            logger.error("[-] Failed to send data to OpenSearch: %s",ex)
            return f"Failed to send data to OpenSearch: {ex}"

        stop = perf_counter()
        execution_time = stop - start

        logger.info("[+] The response from OpenSearch-server: %s", response)
        return f"[+] The response from OpenSearch-server: {response}. \nExecution time: {execution_time:.2f} seconds."

    return inner
