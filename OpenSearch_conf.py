# ====------------------RAVEN-----------------------===
# This file is used for init all opensearch configurations

from opensearchpy import OpenSearch
import json
import urllib3
import time
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ConfigureOpenSearch:
    # Provide the required information for OpenSearch login
    def __init__(self, host_ip, username, password, host_port, index_name, ssl_bool, verify_ssl_bool):
        self.host = host_ip            # IP of OpenSearch server-host
        self.user = username           # Username of admin
        self.passwd = password         # Password of admin
        self.port = host_port          # Port assigned for connection
        self.index = index_name        # Index name assigned for logs
        self.ssl_ON_OFF = ssl_bool     # Should be true by default
        self.ssl_verification = verify_ssl_bool  # False by default

        self.last_sort = None
        self.poll_interval = 1.5
        self.batch_size = 1000

        self.EstablishConnection = OpenSearch(
            hosts=[{"host": self.host, "port": self.port}],
            http_auth=(self.user, self.passwd),
            use_ssl=self.ssl_ON_OFF,
            verify_certs=self.ssl_verification,  # By default false as we don't have SSL certs
            ssl_show_warn=False                  # Disable warnings since we don't have certs
        )

    def SetIndex(self, IndexName):
        self.index = IndexName

    def GetIndex(self):
        return self.index

    def get_last_log_position(self):
        res = self.EstablishConnection.search(
            index=self.GetIndex(),
            body={
                "size": 1,
                "sort": [
                    {"@timestamp": {"order": "desc"}},
                    {"_id": {"order": "desc"}}
                ],
                "query": {"match_all": {}}
            }
        )

        hits = res["hits"]["hits"]
        if hits:
            self.last_sort = hits[0]["sort"]


    # ==== ADDED: Extract URL label from log ====
    def extract_url_label(self, log_source):
        """
        Adjust this path depending on your OpenSearch log structure.
        Current assumed structure: {"url": {"label": "..."}}
        """
        try:
            return log_source.get("url", {}).get("label", None)
        except:
            return None


    # ==== ADDED: Send URL label to SOAR (TDARE) ====
    def send_to_soar(self, url_label):
        """
        Replace this with your real TDARE SOAR integration.
        """
        print(f"[SOAR] URL Label sent: {url_label}")


    def tail(self):
        print(f"Tailing index '{self.GetIndex()}'...\n")

        if self.last_sort is None:
            self.get_last_log_position()

        while True:
            try:
                query = {
                    "size": self.batch_size,
                    "sort": [
                        {"@timestamp": {"order": "asc"}},
                        {"_id": {"order": "asc"}}
                    ],
                    "query": {"match_all": {}},
                    "search_after": self.last_sort
                }
                
                res = self.EstablishConnection.search(index=self.GetIndex(), body=query)
                hits = res["hits"]["hits"]

                if hits:
                    for hit in hits:
                        print(json.dumps(hit["_source"], indent=4))

                        # ==== ADDED: Extract URL label and send to SOAR ====
                        url_label = self.extract_url_label(hit["_source"])
                        if url_label:
                            self.send_to_soar(url_label)
                        # ==================================================

                        self.last_sort = hit["sort"]

                time.sleep(self.poll_interval)

            except KeyboardInterrupt:
                print("\nStopped tailing.")
                break

            except Exception as e:
                print(f"Error: {e}")
                time.sleep(self.poll_interval)

    def ConnectionStatus(self):
        try:
            status = self.EstablishConnection.info()
            status_jsonformat = json.dumps(status, indent=4)
            print(status_jsonformat)
            return status
        except Exception as e:
            print(e)
            return None


if __name__ == "__main__":
    Connection = ConfigureOpenSearch(
        "127.0.0.1",
        "admin",
        "123@DodgeFord_BMWgtr",
        9200,
        "test_manual",
        True,
        False
    )

    print("---------------------------")
    Connection.tail()  # Start tailing the index
