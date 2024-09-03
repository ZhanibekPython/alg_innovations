import httpx
from logging import getLogger
from time import perf_counter
from config import PASSWORD, USERNAME, SSL_CERTIFICATE

logger = getLogger(__name__)

def send_data_to_opensearch(func):
    """Function-decorator. Returns execution time and sends filtered data to OpenSearch server asynchronously."""

    async def inner(*args, **kwargs):
        start = perf_counter()

        try:
            data = await func(*args, **kwargs)
        except Exception as ex:
            logger.error("[-] Failed to get data from function: %s", ex)
            return f"Failed to get data from function: {ex}"

        try:
            async with httpx.AsyncClient(verify=SSL_CERTIFICATE) as client:
                response = await client.post(
                    url="https://localhost:9200/python_index/_doc/",
                    auth=(USERNAME, PASSWORD),
                    json=data,
                    headers={"Content-Type": "application/json"},
                )
        except httpx.HTTPError as ex:
            logger.error("[-] Failed to send data to OpenSearch: %s", ex)
            return f"Failed to send data to OpenSearch: {ex}"

        stop = perf_counter()
        execution_time = stop - start

        logger.info("[+] The response from OpenSearch-server: %s", response.text)
        return f"[+] The response from OpenSearch-server: {response.text}. \nExecution time: {execution_time:.2f} seconds."

    return inner
