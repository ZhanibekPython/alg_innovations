import asyncio
import httpx
import logging.config
import json
from art import tprint, DEFAULT_FONT
from datetime import datetime
from collections import defaultdict
from async_send_to_opensearch import send_data_to_opensearch
from config import URL, PASSWORD, USERNAME, SSL_CERTIFICATE, HEADERS


with open("logging.conf") as log_file:
    config = json.load(log_file)

logging.config.dictConfig(config=config)
logger = logging.getLogger(__name__)


@send_data_to_opensearch
async def get_data_from_opensearch(url: str = URL, username: str = USERNAME, password: str = PASSWORD):
    """This func gets data from OpenSearch server, analyzes and returns filtered data for OpenSearch-dashboard"""

    auth = (username, password)

    try:
        async with httpx.AsyncClient(verify=SSL_CERTIFICATE) as client:
            response = await client.get(url, auth=auth, headers=HEADERS)
            if response.status_code == 200:
                data = response.json()

                cpu_metrics = defaultdict(list)
                memory_metrics = defaultdict(set)
                syslog_metrics = defaultdict(set)
                time = {'time': str(datetime.fromisoformat(
                    data.get("hits").get("hits")[0].get("_source").get("@timestamp").split(".")[0]))}

                metrics = data.get("hits").get("hits")[:]
                for metric in metrics:
                    for k, v in metric["_source"].items():
                        if isinstance(v, (int, float)):
                            if isinstance(v, float):
                                cpu_metrics[k].append(v)
                            elif isinstance(v, int):
                                memory_metrics[k].add(v)
                        else:
                            syslog_metrics[k].add(v) if k not in ("@timestamp", "MESSAGE") else ""

                cpu_metrics = {k: sum(v) for k, v in cpu_metrics.items()}
                memory_metrics = {k: sum(list(v)) for k, v in memory_metrics.items()}
                syslog_metrics = {k: list(v) for k, v in syslog_metrics.items()}

                logger.info("Returning serialized data")
                return json.dumps(obj={**time, **cpu_metrics, **memory_metrics, **syslog_metrics})

            else:
                logger.error("[-] Request failed with status %s", response.status_code)
                return "An error occurred while data operation"

    except httpx.HTTPError as error:
        logger.error("[-] Error %s", error)
        return f"{error}. Do something, bro"


async def main():
    tprint("ALG_INNOVATIONS", font=DEFAULT_FONT)
    result = await get_data_from_opensearch()
    print(result)


if __name__ == "__main__":
    logger.info("[+] Starting the data transfer to OpenSearch")
    print("[+] Starting the data transfer to OpenSearch")
    asyncio.run(main())
    print("[+] Transfer data to OpenSearch completed")
    logger.info("[+] Transfer data to OpenSearch completed")
