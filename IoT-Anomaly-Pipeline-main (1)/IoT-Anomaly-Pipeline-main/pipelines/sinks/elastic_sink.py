from elasticsearch import Elasticsearch
class ElasticSink:
    def __init__(self, url, index):
        self.es = Elasticsearch(url); self.index = index
    def emit(self, event):
        if event["severity"]["level"] != "IGNORE":
            self.es.index(index=self.index, document=event)
    def close(self): pass
